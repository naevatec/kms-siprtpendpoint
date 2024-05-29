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
};

/* these numbers are nothing but wild guesses and don't reflect any reality */
#define DEFAULT_MAX_KBPS -1
#define DEFAULT_MAX_BUCKET_SIZE -1

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
  GMainLoop *loop;

  GST_TRACE_OBJECT (trafficshaper, "TASK: begin");

  g_mutex_lock (&trafficshaper->loop_mutex);
  loop = g_main_loop_ref (trafficshaper->main_loop);
  trafficshaper->running = TRUE;
  GST_TRACE_OBJECT (trafficshaper, "TASK: signal start");
  g_cond_signal (&trafficshaper->start_cond);
  g_mutex_unlock (&trafficshaper->loop_mutex);

  GST_TRACE_OBJECT (trafficshaper, "TASK: run");
  g_main_loop_run (loop);
  g_main_loop_unref (loop);

  g_mutex_lock (&trafficshaper->loop_mutex);
  GST_TRACE_OBJECT (trafficshaper, "TASK: pause");
  gst_pad_pause_task (trafficshaper->srcpad);
  trafficshaper->running = FALSE;
  GST_TRACE_OBJECT (trafficshaper, "TASK: signal end");
  g_cond_signal (&trafficshaper->start_cond);
  g_mutex_unlock (&trafficshaper->loop_mutex);
  GST_TRACE_OBJECT (trafficshaper, "TASK: end");
}

static gboolean
_main_loop_quit_and_remove_source (gpointer user_data)
{
  GMainLoop *main_loop = user_data;
  GST_DEBUG ("MAINLOOP: Quit %p", main_loop);
  g_main_loop_quit (main_loop);
  g_assert (!g_main_loop_is_running (main_loop));
  return FALSE;                 /* Remove source */
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
      GMainContext *main_context = g_main_context_new ();
      trafficshaper->main_loop = g_main_loop_new (main_context, FALSE);
      g_main_context_unref (main_context);

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
      GSource *source;
      guint id;

      /* Adds an Idle Source which quits the main loop from within.
       * This removes the possibility for run/quit race conditions. */
      GST_TRACE_OBJECT (trafficshaper, "DEACT: Stopping main loop on deactivate");
      source = g_idle_source_new ();
      g_source_set_callback (source, _main_loop_quit_and_remove_source,
          g_main_loop_ref (trafficshaper->main_loop),
          (GDestroyNotify) g_main_loop_unref);
      id = g_source_attach (source,
          g_main_loop_get_context (trafficshaper->main_loop));
      g_source_unref (source);
      g_assert_cmpuint (id, >, 0);
      g_main_loop_unref (trafficshaper->main_loop);
      trafficshaper->main_loop = NULL;

      GST_TRACE_OBJECT (trafficshaper, "DEACT: Wait for mainloop and task to pause");
      g_assert (trafficshaper->running);
      while (trafficshaper->running)
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
push_buffer_ctx_push (PushBufferCtx * ctx)
{
  GST_DEBUG_OBJECT (ctx->pad, "Pushing buffer now");
  gst_pad_push (ctx->pad, gst_buffer_ref (ctx->buf));
  return FALSE;
}


static GstFlowReturn
gst_traffic_shaper_delay_buffer (GstTrafficShaper * trafficshaper, GstBuffer * buf, gint64 delay)
{
  GstFlowReturn ret = GST_FLOW_OK;

  g_mutex_lock (&trafficshaper->loop_mutex);
  if ((trafficshaper->main_loop != NULL) && (delay > 0)){
    PushBufferCtx *ctx;
    GSource *source;
    gint64 ready_time, now_time;

    ctx = push_buffer_ctx_new (trafficshaper->srcpad, buf);

    source = g_source_new (&gst_traffic_shaper_source_funcs, sizeof (GSource));
    now_time = g_get_monotonic_time ();
    ready_time = now_time + delay;

    trafficshaper->last_ready_time = ready_time;
    GST_DEBUG_OBJECT (trafficshaper, "Delaying packet by %" G_GINT64_FORMAT "us",
        delay);

    g_source_set_ready_time (source, ready_time);
    g_source_set_callback (source, (GSourceFunc) push_buffer_ctx_push,
        ctx, (GDestroyNotify) push_buffer_ctx_free);
    g_source_attach (source, g_main_loop_get_context (trafficshaper->main_loop));
    g_source_unref (source);
  } else {
    GST_DEBUG_OBJECT (trafficshaper, "Not delaying packet, sending immediately");
    ret = gst_pad_push (trafficshaper->srcpad, gst_buffer_ref (buf));
  }
  g_mutex_unlock (&trafficshaper->loop_mutex);

  return ret;
}

static gint
gst_traffic_shaper_get_tokens (GstTrafficShaper * trafficshaper)
{
  gint tokens = 0;
  GstClockTimeDiff elapsed_time = 0;
  GstClockTime current_time = 0;
  GstClockTimeDiff token_time;
  GstClock *clock;

  /* check for umlimited kbps and fill up the bucket if that is the case,
   * if not, calculate the number of tokens to add based on the elapsed time */
  if (trafficshaper->max_kbps == -1)
    return trafficshaper->max_bucket_size * 1000 - trafficshaper->bucket_size;

  /* get the current time */
  clock = gst_element_get_clock (GST_ELEMENT_CAST (trafficshaper));
  if (clock == NULL) {
    GST_WARNING_OBJECT (trafficshaper, "No clock, can't get the time");
  } else {
    current_time = gst_clock_get_time (clock);
  }

  /* get the elapsed time */
  if (GST_CLOCK_TIME_IS_VALID (trafficshaper->prev_time)) {
    if (current_time < trafficshaper->prev_time) {
      GST_WARNING_OBJECT (trafficshaper, "Clock is going backwards!!");
    } else {
      elapsed_time = GST_CLOCK_DIFF (trafficshaper->prev_time, current_time);
    }
  } else {
    trafficshaper->prev_time = current_time;
  }

  /* calculate number of tokens and how much time is "spent" by these tokens */
  tokens =
      gst_util_uint64_scale_int (elapsed_time, trafficshaper->max_kbps * 1000,
      GST_SECOND);
  token_time =
      gst_util_uint64_scale_int (GST_SECOND, tokens, trafficshaper->max_kbps * 1000);

  /* increment the time with how much we spent in terms of whole tokens */
  trafficshaper->prev_time += token_time;
  gst_object_unref (clock);
  return tokens;
}

static gint64
gst_traffic_shaper_token_bucket (GstTrafficShaper * trafficshaper, GstBuffer * buf)
{
  long buffer_size;
  gint tokens;
  gint64 buffer_delay_us = 0L;

  /* with an unlimited bucket-size, we have nothing to do */
  if (trafficshaper->max_bucket_size == -1)
    return buffer_delay_us;

  /* get buffer size in bits */
  buffer_size = gst_buffer_get_size (buf) * 8;
  tokens = gst_traffic_shaper_get_tokens (trafficshaper);

  trafficshaper->bucket_size = MIN (G_MAXINT, trafficshaper->bucket_size + tokens);
  GST_LOG_OBJECT (trafficshaper,
      "Adding %d tokens to bucket (contains %" G_GSIZE_FORMAT " tokens)",
      tokens, trafficshaper->bucket_size);

  if (trafficshaper->max_bucket_size != -1 && trafficshaper->bucket_size >
      trafficshaper->max_bucket_size * 1000)
    trafficshaper->bucket_size = trafficshaper->max_bucket_size * 1000;

  if (buffer_size > trafficshaper->bucket_size) {
    GST_DEBUG_OBJECT (trafficshaper,
        "Buffer size (%" G_GSIZE_FORMAT ") exeedes bucket size (%"
        G_GSIZE_FORMAT "), delayig buffer to keep max bitrate", buffer_size, trafficshaper->bucket_size);
    buffer_delay_us = buffer_size - trafficshaper->bucket_size;
    buffer_delay_us *= 1000; //scale change to measure bits per microsecond
    buffer_delay_us /= (trafficshaper->max_kbps);
  }

  trafficshaper->bucket_size -= buffer_size;
  GST_LOG_OBJECT (trafficshaper,
      "Buffer taking %" G_GSIZE_FORMAT " tokens (%ld left), delayed %ld us",
      buffer_size, trafficshaper->bucket_size, buffer_delay_us);
  return buffer_delay_us;
}

static GstFlowReturn
gst_traffic_shaper_chain (GstPad * pad, GstObject * parent, GstBuffer * buf)
{
  GstTrafficShaper *trafficshaper = GST_TRAFFIC_SHAPER (parent);
  GstFlowReturn ret = GST_FLOW_OK;
  gint64 buffer_delay;

  buffer_delay = gst_traffic_shaper_token_bucket (trafficshaper, buf);

  ret = gst_traffic_shaper_delay_buffer (trafficshaper, buf, buffer_delay);

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
      trafficshaper->max_bucket_size = g_value_get_int (value);
      if (trafficshaper->max_bucket_size != -1)
        trafficshaper->bucket_size = trafficshaper->max_bucket_size * 1000;
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
      g_value_set_int (value, trafficshaper->max_bucket_size);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}


static void
gst_traffic_shaper_init (GstTrafficShaper * trafficshaper)
{
  trafficshaper->srcpad =
      gst_pad_new_from_static_template (&gst_traffic_shaper_src_template, "src");
  trafficshaper->sinkpad =
      gst_pad_new_from_static_template (&gst_traffic_shaper_sink_template, "sink");

  gst_element_add_pad (GST_ELEMENT (trafficshaper), trafficshaper->srcpad);
  gst_element_add_pad (GST_ELEMENT (trafficshaper), trafficshaper->sinkpad);

  g_mutex_init (&trafficshaper->loop_mutex);
  g_cond_init (&trafficshaper->start_cond);
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
      g_param_spec_int ("max-bucket-size", "Maximum Bucket Size (Kb)",
          "The size of the token bucket, related to burstiness resilience "
          "(-1 = unlimited)", -1, G_MAXINT, DEFAULT_MAX_BUCKET_SIZE,
          G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS));
}

gboolean
gst_traffic_shaper_plugin_init (GstPlugin * plugin)
{
  return gst_element_register (plugin, PLUGIN_NAME, GST_RANK_NONE,
      GST_TYPE_TRAFFIC_SHAPER);
}

