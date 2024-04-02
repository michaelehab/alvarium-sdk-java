
/*******************************************************************************
 * Copyright 2023 Dell Inc.
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
package com.alvarium.annotators;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;

import com.alvarium.SdkInfo;
import com.alvarium.contracts.Annotation;
import com.alvarium.contracts.AnnotationType;
import com.alvarium.hash.HashProvider;
import com.alvarium.hash.HashType;
import com.alvarium.sign.KeyInfo;
import com.alvarium.sign.SignProvider;
import com.alvarium.utils.PropertyBag;

/**
 * a dummy annotator to be used in unit tests
 */
class MockAnnotator implements Annotator {
  private final MockAnnotatorConfig mockCfg;
  private final HashProvider hash;
  private final HashType hashType;
  private final AnnotationType kind;
  private final KeyInfo publicKey;

  protected MockAnnotator(MockAnnotatorConfig mockCfg, SdkInfo cfg, HashProvider hash) {
    this.mockCfg = mockCfg;
    this.hash = hash;
    this.hashType = cfg.getHash().getType();
    this.kind = AnnotationType.MOCK;
    this.publicKey = cfg.getSignature().getPublicKey();
  }

  public Annotation execute(PropertyBag ctx, byte[] data) throws AnnotatorException {
    try {
      final String key = hash.derive(data);
      final String host = InetAddress.getLocalHost().getHostName();
      final String sig = this.publicKey.getType().toString();

      final Annotation annotation = new Annotation(key, hashType, host, kind, sig, mockCfg.getShouldSatisfy(), Instant.now());
      return annotation;
    } catch (UnknownHostException e) {
      throw new AnnotatorException("Could not get hostname", e);
    }
  } 
}
