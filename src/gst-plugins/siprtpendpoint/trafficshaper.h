#ifndef __GST_TRAFFIC_SHAPER_H__
#define __GST_TRAFFIC_SHAPER_H__

#include <commons/kmselement.h>

G_BEGIN_DECLS

/* #define's don't like whitespacey bits */
#define GST_TYPE_TRAFFIC_SHAPER \
  (gst_traffic_shaper_get_type())
#define GST_TRAFFIC_SHAPER(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), \
  GST_TYPE_TRAFFIC_SHAPER,GstTrafficShaper))
#define GST_TRAFFIC_SHAPER_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass), \
  GST_TYPE_TRAFFIC_SHAPER,GstTrafficShaperClass))
#define GST_IS_TRAFFIC_SHAPER(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_TRAFFIC_SHAPER))
#define GST_IS_TRAFFIC_SHAPER_CLASS(obj) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_TRAFFIC_SHAPER))

typedef struct _GstTrafficShaper GstTrafficShaper;
typedef struct _GstTrafficShaperClass GstTrafficShaperClass;

struct _GstTrafficShaper
{
  GstElement parent;

  GstPad *sinkpad;
  GstPad *srcpad;

  GMutex loop_mutex;
  GCond start_cond;
  GMainLoop *main_loop;
  gboolean running;
  long bucket_size;
  GstClockTime prev_time;
  gint64 last_ready_time;

  /* properties */
  gint max_kbps;
  gint max_bucket_size;
};

struct _GstTrafficShaperClass
{
  GstElementClass parent_class;
};

GType gst_traffic_shaper_get_type (void);
gboolean gst_traffic_shaper_plugin_init (GstPlugin * plugin);

G_END_DECLS

#endif /* __GST_TRAFFIC_SHAPER_H__ */