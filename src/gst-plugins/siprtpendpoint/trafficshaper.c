
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "trafficshaper.h"
#include <string.h>
#include <math.h>
#include <float.h>

#define PLUGIN_NAME "trafficshaper"

GST_DEBUG_CATEGORY (trafficshaper_debug_category);
#define GST_CAT_DEFAULT (trafficshaper_debug_category)


enum
{
  PROP_0,
  PROP_MAX_KBPS,
  PROP_MAX_BUCKET_SIZE,
  PROP_MAX_BUCKET_STORAGE,
  PROP_CURRENT_BUCKET_SIZE,
};

/* these numbers are nothing but wild guesses and don't reflect any reality */
#define DEFAULT_MAX_KBPS -1
#define DEFAULT_MAX_BUCKET_SIZE -1
#define DEFAULT_MAX_BUCKET_STORAGE 3000000

#define DROP_BUFFER_MAGIC -1000

static GstStaticPadTemplate gst_traffic_shaper_sink_template =
GST_STATIC_PAD_TEMPLATE ("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

static GstStaticPadTemplate gst_traffic_shaper_src_template =
GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

G_DEFINE_TYPE_WITH_CODE (GstTrafficShaper, gst_traffic_shaper,
    GST_TYPE_ELEMENT,
    GST_DEBUG_CATEGORY_INIT (trafficshaper_debug_category, PLUGIN_NAME,
        0, "debug category for traffic shaper element"));


static gboolean
gst_traffic_shaper_source_dispatch (GSource * source,
    GSourceFunc callback, gpointer user_data)
{
  callback (user_data);
  return FALSE;
}

GSourceFuncs gst_traffic_shaper_source_funcs = {
  NULL,                         /* prepare */
  NULL,                         /* check */
  gst_traffic_shaper_source_dispatch,
  NULL                          /* finalize */
};

static void
gst_traffic_shaper_loop (GstTrafficShaper * trafficshaper)
{
  GST_TRACE_OBJECT (trafficshaper, "TASK: begin");

  g_mutex_lock (&trafficshaper->loop_mutex);
  trafficshaper->main_loop = kms_loop_new ();
  trafficshaper->running = TRUE;
  GST_TRACE_OBJECT (trafficshaper, "TASK: signal start");
  g_cond_signal (&trafficshaper->start_cond);

  GST_TRACE_OBJECT (trafficshaper, "TASK: run");
  while (trafficshaper->running)
    g_cond_wait (&trafficshaper->stop_cond, &trafficshaper->loop_mutex);

  GST_TRACE_OBJECT (trafficshaper, "TASK: pause");
  gst_pad_pause_task (trafficshaper->srcpad);
  trafficshaper->running = FALSE;
  GST_TRACE_OBJECT (trafficshaper, "TASK: signal end");
  gst_object_unref(trafficshaper->main_loop);
  trafficshaper->main_loop = NULL;
  g_cond_signal (&trafficshaper->start_cond);
  g_mutex_unlock (&trafficshaper->loop_mutex);
  GST_TRACE_OBJECT (trafficshaper, "TASK: end");
}


static gboolean
gst_traffic_shaper_src_activatemode (GstPad * pad, GstObject * parent,
    GstPadMode mode, gboolean active)
{
  GstTrafficShaper *trafficshaper = GST_TRAFFIC_SHAPER (parent);
  gboolean result = FALSE;

  g_mutex_lock (&trafficshaper->loop_mutex);
  if (active) {
    if (trafficshaper->main_loop == NULL) {
      GST_TRACE_OBJECT (trafficshaper, "ACT: Starting task on srcpad");
      result = gst_pad_start_task (trafficshaper->srcpad,
          (GstTaskFunction) gst_traffic_shaper_loop, trafficshaper, NULL);

      GST_TRACE_OBJECT (trafficshaper, "ACT: Wait for task to start");
      g_assert (!trafficshaper->running);
      while (!trafficshaper->running)
        g_cond_wait (&trafficshaper->start_cond, &trafficshaper->loop_mutex);
      GST_TRACE_OBJECT (trafficshaper, "ACT: Task on srcpad started");
    }
  } else {
    if (trafficshaper->main_loop != NULL) {
      /* Adds an Idle Source which quits the main loop from within.
       * This removes the possibility for run/quit race conditions. */
      GST_TRACE_OBJECT (trafficshaper, "DEACT: Stopping main loop on deactivate");
      trafficshaper->running = FALSE;
      g_cond_signal (&trafficshaper->stop_cond);

      GST_TRACE_OBJECT (trafficshaper, "DEACT: Wait for mainloop and task to pause");
      while (trafficshaper->main_loop != NULL)
        g_cond_wait (&trafficshaper->start_cond, &trafficshaper->loop_mutex);

      GST_TRACE_OBJECT (trafficshaper, "DEACT: Stopping task on srcpad");
      result = gst_pad_stop_task (trafficshaper->srcpad);
      GST_TRACE_OBJECT (trafficshaper, "DEACT: Mainloop and GstTask stopped");
    }
  }
  g_mutex_unlock (&trafficshaper->loop_mutex);

  return result;
}

typedef struct
{
  GstPad *pad;
  GstBuffer *buf;
} PushBufferCtx;

static inline PushBufferCtx *
push_buffer_ctx_new (GstPad * pad, GstBuffer * buf)
{
  PushBufferCtx *ctx = g_slice_new (PushBufferCtx);
  ctx->pad = gst_object_ref (pad);
  ctx->buf = gst_buffer_ref (buf);
  return ctx;
}

static inline void
push_buffer_ctx_free (PushBufferCtx * ctx)
{
  if (G_LIKELY (ctx != NULL)) {
    gst_buffer_unref (ctx->buf);
    gst_object_unref (ctx->pad);
    g_slice_free (PushBufferCtx, ctx);
  }
}

static gboolean
push_buffer_ctx_push (gpointer udata)
{
  PushBufferCtx * ctx = (PushBufferCtx*) udata;

  GST_DEBUG_OBJECT (ctx->pad, "Pushing buffer now");
  gst_pad_push (ctx->pad, gst_buffer_ref (ctx->buf));
  return FALSE;
}


static GstFlowReturn
gst_traffic_shaper_delay_buffer (GstTrafficShaper * trafficshaper, GstBuffer * buf, gint64 delay)
{
  GstFlowReturn ret = GST_FLOW_OK;
  gboolean delayed = FALSE;

  if (delay > 0) {
    g_mutex_lock (&trafficshaper->loop_mutex);
    if (trafficshaper->main_loop != NULL) {
      PushBufferCtx *ctx;

      ctx = push_buffer_ctx_new (trafficshaper->srcpad, buf);

      GST_DEBUG_OBJECT (trafficshaper, "Delaying packet by %" G_GINT64_FORMAT "ms", delay);

      kms_loop_timeout_add (trafficshaper->main_loop, delay, push_buffer_ctx_push, ctx);
      delayed = TRUE;
    }
    g_mutex_unlock (&trafficshaper->loop_mutex);
  }

  if (!delayed) {
    GST_DEBUG_OBJECT (trafficshaper, "Not delaying packet, sending immediately");
    ret = gst_pad_push (trafficshaper->srcpad, gst_buffer_ref (buf));
  }

  return ret;
}

static gint64
gst_traffic_shaper_get_tokens (GstTrafficShaper * trafficshaper)
{
  gint64 tokens = 0;
  gint64 elapsed_time = 0;  // Measured in us
  gint64 current_time = 0;  // Measured in us
  gint64 token_time;

  /* check for umlimited kbps and fill up the bucket if that is the case,
   * if not, calculate the number of tokens to add based on the elapsed time */
  if (trafficshaper->max_kbps == -1)
    return trafficshaper->max_bucket_size - trafficshaper->bucket_size;

  /* get the current time */
  current_time = g_get_monotonic_time();
  GST_DEBUG_OBJECT(trafficshaper, "current time is %ld", current_time);

  /* get the elapsed time */
  if (GST_CLOCK_TIME_IS_VALID (trafficshaper->prev_time)) {
    if (current_time < trafficshaper->prev_time) {
      GST_WARNING_OBJECT (trafficshaper, "Clock is going backwards!!");
      elapsed_time = 0;
      trafficshaper->prev_time = current_time;
    } else {
      elapsed_time = current_time - trafficshaper->prev_time;
    }
    /* calculate number of tokens and how much time is "spent" by these tokens */
    tokens =
        gst_util_uint64_scale (elapsed_time, trafficshaper->max_kbps * 1000,
        G_USEC_PER_SEC);
    if (tokens < 0) {
      // Cannot add negative tokens
      GST_WARNING_OBJECT(trafficshaper, "Added token cannot be negative, some overloading happened, tokens = %ld", tokens);
      tokens = 0;
      trafficshaper->prev_time = current_time;
    } else {
      token_time =
          gst_util_uint64_scale (G_USEC_PER_SEC, tokens, trafficshaper->max_kbps * 1000);
      /* increment the time with how much we spent in terms of whole tokens */
      trafficshaper->prev_time += token_time;
    }
  } else {
    // First time we get the tokens, we can provide the max bucket size, no added tokens
    trafficshaper->prev_time = current_time;
    tokens = 0;
  }

  return tokens;
}

static gint64
gst_traffic_shaper_token_bucket (GstTrafficShaper * trafficshaper, GstBuffer * buf)
{
  long buffer_size;
  gint64 tokens;
  gint64 buffer_delay_us = 0L;
  gint max_storage_size;

  /* with an unlimited bucket-size, we have nothing to do */
  if (trafficshaper->max_bucket_size == -1)
    return buffer_delay_us;

  /* get buffer size in bits */
  buffer_size = gst_buffer_get_size (buf) * 8;
  tokens = gst_traffic_shaper_get_tokens (trafficshaper);

  trafficshaper->bucket_size = MIN (G_MAXLONG, trafficshaper->bucket_size + tokens);
  GST_LOG_OBJECT (trafficshaper,
      "Adding %ld tokens to bucket (contains %ld tokens)",
      tokens, trafficshaper->bucket_size);

  if ((trafficshaper->max_bucket_size != -1) && (trafficshaper->bucket_size >
      (trafficshaper->max_bucket_size)))
    trafficshaper->bucket_size = trafficshaper->max_bucket_size;

  if (buffer_size > trafficshaper->bucket_size) {
    GST_DEBUG_OBJECT (trafficshaper,
        "Buffer size (%" G_GSIZE_FORMAT ") exeedes bucket size (%ld), delayig buffer to keep max bitrate", buffer_size, trafficshaper->bucket_size);
    buffer_delay_us = buffer_size - trafficshaper->bucket_size;
    buffer_delay_us *= 1000; //scale change to measure bits per microsecond
    buffer_delay_us /= (trafficshaper->max_kbps);
  }

  if (trafficshaper->max_storage_size != -1)  {
    // Keep storage bounded
    max_storage_size = trafficshaper->max_storage_size;
    if ((trafficshaper->bucket_size + max_storage_size - buffer_size) >= 0) {  
      // We are storing less than the maximum allowed
      trafficshaper->bucket_size -= buffer_size; // Greater than -max_storage_size
      GST_LOG_OBJECT (trafficshaper,
          "Buffer taking %" G_GSIZE_FORMAT " tokens (%ld left), delayed %ld us",
          buffer_size, trafficshaper->bucket_size, buffer_delay_us);
      return buffer_delay_us/1000;
    } else {
      // We would need to store more than allowed, so packet is dropped. bucket size is unchanged as no tokens are consumed
      GST_LOG_OBJECT (trafficshaper,
          "Buffer taking %" G_GSIZE_FORMAT " tokens (%ld left), will be dropped as storage capacity is full %ld ",
          buffer_size, trafficshaper->bucket_size, trafficshaper->max_storage_size);
      return DROP_BUFFER_MAGIC;
    }
  } else {
    // RIsk, storage is unbounded potential risk of memory high consumption
    trafficshaper->bucket_size -= buffer_size;
    GST_LOG_OBJECT (trafficshaper,
        "Buffer taking %" G_GSIZE_FORMAT " tokens (%ld left), delayed %ld us",
        buffer_size, trafficshaper->bucket_size, buffer_delay_us);
    return buffer_delay_us/1000;
  }
}

static GstFlowReturn
gst_traffic_shaper_chain (GstPad * pad, GstObject * parent, GstBuffer * buf)
{
  GstTrafficShaper *trafficshaper = GST_TRAFFIC_SHAPER (parent);
  GstFlowReturn ret = GST_FLOW_OK;
  gint64 buffer_delay_ms;

  buffer_delay_ms = gst_traffic_shaper_token_bucket (trafficshaper, buf);

  if (buffer_delay_ms == DROP_BUFFER_MAGIC) {
    // Drop buffer
    ret = GST_FLOW_OK;
  } else {
    ret = gst_traffic_shaper_delay_buffer (trafficshaper, buf, buffer_delay_ms);
  }

  gst_buffer_unref (buf);
  return ret;
}


static void
gst_traffic_shaper_set_property (GObject * object,
    guint prop_id, const GValue * value, GParamSpec * pspec)
{
  GstTrafficShaper *trafficshaper = GST_TRAFFIC_SHAPER (object);

  switch (prop_id) {
    case PROP_MAX_KBPS:
      trafficshaper->max_kbps = g_value_get_int (value);
      break;
    case PROP_MAX_BUCKET_SIZE:
      trafficshaper->max_bucket_size = 8 * g_value_get_long (value);
      if (trafficshaper->max_bucket_size >= 0) {
        trafficshaper->bucket_size = trafficshaper->max_bucket_size;
      } else {
        trafficshaper->max_bucket_size = -1;
      }
      break;
    case PROP_MAX_BUCKET_STORAGE:
      trafficshaper->max_storage_size = 8 * g_value_get_long (value);
      if (trafficshaper->max_storage_size < 0) {
        trafficshaper->max_storage_size = -1;
      }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_traffic_shaper_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec)
{
  GstTrafficShaper *trafficshaper = GST_TRAFFIC_SHAPER (object);

  switch (prop_id) {
    case PROP_MAX_KBPS:
      g_value_set_int (value, trafficshaper->max_kbps);
      break;
    case PROP_MAX_BUCKET_SIZE:
      g_value_set_long (value, trafficshaper->max_bucket_size/8);
      break;
    case PROP_MAX_BUCKET_STORAGE:
      g_value_set_long (value, trafficshaper->max_storage_size/8);
      break;
    case PROP_CURRENT_BUCKET_SIZE:
      g_value_set_long (value, trafficshaper->bucket_size/8);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}


static void
gst_traffic_shaper_init (GstTrafficShaper * trafficshaper)
{
  trafficshaper->bucket_size = 0;
  trafficshaper->max_bucket_size = -1;
  trafficshaper->max_kbps = -1;
  trafficshaper->max_storage_size = -1;

  trafficshaper->srcpad =
      gst_pad_new_from_static_template (&gst_traffic_shaper_src_template, "src");
  trafficshaper->sinkpad =
      gst_pad_new_from_static_template (&gst_traffic_shaper_sink_template, "sink");

  gst_element_add_pad (GST_ELEMENT (trafficshaper), trafficshaper->srcpad);
  gst_element_add_pad (GST_ELEMENT (trafficshaper), trafficshaper->sinkpad);

  g_mutex_init (&trafficshaper->loop_mutex);
  g_cond_init (&trafficshaper->start_cond);
  g_cond_init (&trafficshaper->stop_cond);
  trafficshaper->main_loop = NULL;
  trafficshaper->prev_time = GST_CLOCK_TIME_NONE;

  GST_OBJECT_FLAG_SET (trafficshaper->sinkpad,
      GST_PAD_FLAG_PROXY_CAPS | GST_PAD_FLAG_PROXY_ALLOCATION);

  gst_pad_set_chain_function (trafficshaper->sinkpad,
      GST_DEBUG_FUNCPTR (gst_traffic_shaper_chain));
  gst_pad_set_activatemode_function (trafficshaper->srcpad,
      GST_DEBUG_FUNCPTR (gst_traffic_shaper_src_activatemode));
}

static void
gst_traffic_shaper_finalize (GObject * object)
{
  GstTrafficShaper *trafficshaper = GST_TRAFFIC_SHAPER (object);

  g_mutex_clear (&trafficshaper->loop_mutex);
  g_cond_clear (&trafficshaper->start_cond);
  g_cond_clear (&trafficshaper->stop_cond);

  G_OBJECT_CLASS (gst_traffic_shaper_parent_class)->finalize (object);
}

static void
gst_traffic_shaper_dispose (GObject * object)
{
  GstTrafficShaper *trafficshaper = GST_TRAFFIC_SHAPER (object);

  g_assert (trafficshaper->main_loop == NULL);

  G_OBJECT_CLASS (gst_traffic_shaper_parent_class)->dispose (object);
}

static void
gst_traffic_shaper_class_init (GstTrafficShaperClass * klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GstElementClass *gstelement_class = GST_ELEMENT_CLASS (klass);

  gst_element_class_add_static_pad_template (gstelement_class,
      &gst_traffic_shaper_src_template);
  gst_element_class_add_static_pad_template (gstelement_class,
      &gst_traffic_shaper_sink_template);

  gst_element_class_set_metadata (gstelement_class,
      "Traffic Shaping element",
      "Filter/Network",
      "An element that shapes traffic limiting bitrate to specified one with some busrtiness allowance",
      "Saúl Pablo Labajo <slabajo@naevatec.com>");

  gobject_class->dispose = GST_DEBUG_FUNCPTR (gst_traffic_shaper_dispose);
  gobject_class->finalize = GST_DEBUG_FUNCPTR (gst_traffic_shaper_finalize);

  gobject_class->set_property = gst_traffic_shaper_set_property;
  gobject_class->get_property = gst_traffic_shaper_get_property;

  /**
   * GstTrafficShaper:max-kbps:
   *
   * The maximum number of kilobits to let through per second. Setting this
   * property to a positive value enables network congestion simulation using
   * a token bucket algorithm. Also see the "max-bucket-size" property,
   *
   * Since: 1.14
   */
  g_object_class_install_property (gobject_class, PROP_MAX_KBPS,
      g_param_spec_int ("max-kbps", "Maximum Kbps",
          "The maximum number of kilobits to let through per second "
          "(-1 = unlimited)", -1, G_MAXINT, DEFAULT_MAX_KBPS,
          G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS));

  /**
   * GstTrafficShaper:max-bucket-size:
   *
   * The size of the token bucket, related to burstiness resilience.
   *
   * Since: 1.14
   */
  g_object_class_install_property (gobject_class, PROP_MAX_BUCKET_SIZE,
      g_param_spec_long ("max-bucket-size", "Maximum Bucket Size (Bytes)",
          "The size of the token bucket, related to burstiness resilience "
          "(-1 = unlimited)", -1, G_MAXLONG, DEFAULT_MAX_BUCKET_SIZE,
          G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS));
  /**
   * GstTrafficShaper:min-bucket-size:
   *
   * The maximum kbits that can be stored delayed to be traffci shaped.
   *
   * Since: 1.14
   */
  g_object_class_install_property (gobject_class, PROP_MAX_BUCKET_STORAGE,
      g_param_spec_long ("max-bucket-storage", "Maximum delayed storage size Size (Bytes)",
          "The maximum amount of storage allowed for delayed packets in kbits "
          "(-1 = unlimited)", -1, G_MAXLONG, DEFAULT_MAX_BUCKET_STORAGE,
          G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS));
  /**
   * GstTrafficShaper:max-bucket-size:
   *
   * The current size of the token bucket, related to amount of data sotred to be delayed.
   *
   * Since: 1.14
   */
  g_object_class_install_property (gobject_class, PROP_CURRENT_BUCKET_SIZE,
      g_param_spec_long ("current-bucket-size", "Current Bucket Size (Bytes)",
          "The size of the token bucket, if positive no delayed packets pending, if negative it signals the amount of bytes delayed for traffic shaping ", 
          -1, G_MAXLONG, DEFAULT_MAX_BUCKET_SIZE,
          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
}

gboolean
gst_traffic_shaper_plugin_init (GstPlugin * plugin)
{
  return gst_element_register (plugin, PLUGIN_NAME, GST_RANK_NONE,
      GST_TYPE_TRAFFIC_SHAPER);
}

