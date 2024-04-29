package com.alvarium.tag;

import com.alvarium.contracts.LayerType;

public interface TagWriter {
    String getTagValue(LayerType layer);
}