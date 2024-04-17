package com.alvarium.tag;

import com.alvarium.contracts.LayerType;

public class DefaultTagValueGetter implements TagValueGetter{
    // TagEnvKey is an environment key used to associate annotations with specific metadata,
    // aiding in the linkage of scores across different layers of the stack. For instance, in the "app" layer,
    // it is utilized to retrieve the commit SHA of the workload where the application is running,
    // which is instrumental in tracing the impact on the current layer's score from the lower layers.
    private final String TAG_ENV_KEY = "TAG";
    
    @Override
    public String getTagValue(LayerType layer){
        switch(layer){
            case Application:
              return System.getenv(TAG_ENV_KEY) == null ? "" : System.getenv(TAG_ENV_KEY);
            default:
              break;
          }
          return "";
    }
}
