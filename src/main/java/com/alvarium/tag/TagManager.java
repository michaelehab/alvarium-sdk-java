package com.alvarium.tag;

import com.alvarium.contracts.LayerType;

public class TagManager {
    private static TagValueGetter currentTagValueGetter = new DefaultTagValueGetter();
    private static TagValueGetter defaultTagValueGetter = new DefaultTagValueGetter();
    
    public static void setCurrentTagValueGetter(TagValueGetter customGetter){
        currentTagValueGetter = customGetter;
    }

    public static String getTagValue(LayerType layer){
        String tagValue = currentTagValueGetter.getTagValue(layer);
        if (!tagValue.isEmpty()){
            return tagValue;
        }

        return defaultTagValueGetter.getTagValue(layer);
    }

    /*
     * If we want to override default tag value logic for specific layers we can call:
     * TagManager.setCurrentTagValueGetter(new CustomTagValueGetter());
     * So, TagManager.getTagValue uses the current getter logic and falls back to default one
     */
}
