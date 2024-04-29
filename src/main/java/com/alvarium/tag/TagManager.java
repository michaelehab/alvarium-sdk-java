package com.alvarium.tag;

import com.alvarium.contracts.LayerType;

public class TagManager {
    private static TagWriter currentTagWriter = new DefaultTagWriter();
    private static TagWriter defaultTagWriter = new DefaultTagWriter();

    public static void setCurrentTagWriter(TagWriter customGetter){
        currentTagWriter = customGetter;
    }

    public static String getTagValue(LayerType layer){
        String tagValue = currentTagWriter.getTagValue(layer);
        if (!tagValue.isEmpty()){
            return tagValue;
        }

        return defaultTagWriter.getTagValue(layer);
    }

    /*
     * If we want to override default tag value logic for specific layers we can call:
     * TagManager.setCurrentTagWriter(new CustomTagWriter());
     * So, TagManager.getTagValue uses the current getter logic and falls back to default one
     */
}