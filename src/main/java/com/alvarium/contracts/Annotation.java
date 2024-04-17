
/*******************************************************************************
 * Copyright 2021 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/
package com.alvarium.contracts;


import java.io.Serializable;
import java.time.Instant;

import com.alvarium.hash.HashType;
import com.alvarium.serializers.InstantConverter;
import com.alvarium.tag.TagManager;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import de.huxhorn.sulky.ulid.ULID;

/**
 * A java bean that encapsulates all of the data related to a specific annotation.
 * this will be generated by the annotators.
 */
public class Annotation implements Serializable {
  private final String id; 
  private final String key;
  private final HashType hash;
  private final String host;
  private final String tag;
  private final LayerType layer;
  private final AnnotationType kind;
  private String signature;
  private final Boolean isSatisfied;
  private final Instant timestamp;

  public Annotation(String key, HashType hash, String host, LayerType layer, AnnotationType kind, String signature,
      Boolean isSatisfied, Instant timestamp) {
    ULID ulid = new ULID();
    this.id = ulid.nextULID(); 
    this.key = key;
    this.hash = hash;
    this.host = host;
    this.tag = TagManager.getTagValue(layer);
    this.layer = layer;
    this.kind = kind;
    this.signature = signature;
    this.isSatisfied = isSatisfied;
    this.timestamp = timestamp;  
    }

    //setters
    
    public void setSignature(String signature) {
      this.signature = signature;
    }
    
    // getters

    public String getId() {
      return this.id;
    }

    public String getKey() {
      return this.key;
    }

    public HashType getHash() {
      return this.hash;
    }
    
    public String getHost() {
      return this.host;
    }

    public String getTag() {
      return this.tag;
    }

    public LayerType getLayer() {
      return this.layer;
    }

    public AnnotationType getKind() {
      return this.kind;
    }

    public String getSignature() {
      return this.signature;
    }

    public Boolean getIsSatisfied() {
      return this.isSatisfied;
    }

    public Instant getTimestamp() {
      return this.timestamp;
    }

    /**
     * returns the JSON representation of the Annotation object 
     * @return json string representation
     */ 
    public String toJson() {
      Gson gson = new GsonBuilder().registerTypeAdapter(Instant.class, new InstantConverter())
          .create();
      return gson.toJson(this, Annotation.class);
    }

   /**
    * instaniates an Annotation object from a json representation
    * @param json input JSON string
    * @return Annotation Object
    */  
    public static Annotation fromJson(String json) {
      Gson gson = new GsonBuilder().registerTypeAdapter(Instant.class, new InstantConverter())
          .create();
      return gson.fromJson(json, Annotation.class);
    }
}
