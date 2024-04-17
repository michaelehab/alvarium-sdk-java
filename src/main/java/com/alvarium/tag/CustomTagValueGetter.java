package com.alvarium.tag;

import java.util.HashMap;
import java.util.Map;

import com.alvarium.contracts.LayerType;

public class CustomTagValueGetter implements TagValueGetter{
    private final Map<LayerType, String> cache = new HashMap<>();

    @Override
    public String getTagValue(LayerType layer){
        switch(layer){
            case CUSTOM_LAYER: // Placeholder for layer(s) we want to provide custom logic for
              return cache.computeIfAbsent(layer, this::computeTagValue);
            default:
              break;
          }
          return "";
    }

    private String computeTagValue(LayerType layer){
        // Logic to get custom tag value
        return "Custom Tag Value";
    }
}
