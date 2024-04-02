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
package com.alvarium.annotators;

import org.apache.logging.log4j.Logger;

import com.alvarium.contracts.Annotation;
import com.alvarium.hash.HashProvider;
import com.alvarium.hash.HashProviderFactory;
import com.alvarium.hash.HashType;
import com.alvarium.hash.HashTypeException;
import com.alvarium.sign.KeyInfo;
import com.alvarium.sign.SignException;
import com.alvarium.sign.SignProvider;

/**
 * A Util class responsible for carrying out common operations done by the annotators
 */
abstract class AbstractAnnotator {

  protected  Logger logger;

  AbstractAnnotator(Logger logger) {
    this.logger = logger;
  }

  public Logger getLogger() {
    return logger;
  }
  
  /**
   * returns hash of the provided data depending on the given hash type
   * @param type
   * @param data
   * @return
   * @throws AnnotatorException
   */
  protected String deriveHash(HashType type, byte[] data) throws AnnotatorException {
    final HashProviderFactory hashFactory = new HashProviderFactory();
    
    try {
      final HashProvider provider = hashFactory.getProvider(type);
      return provider.derive(data);
    } catch (HashTypeException e) {
      throw new AnnotatorException("cannot hash data.", e);
    }
  }

  /**
   * returns the signature of the given annotation object after converting it to its json
   * representation
   * @param keyInfo
   * @param signature
   * @param annotation
   * @return
   * @throws AnnotatorException
   */
  protected String signAnnotation(KeyInfo keyInfo, SignProvider signature, Annotation annotation) throws 
      AnnotatorException {

    try {
      return signature.sign(keyInfo, annotation.toJson().getBytes());      
    } catch (SignException e) {
      throw new AnnotatorException("cannot sign annotation.", e);
    }
  }

  /**
   * verify the signature of a given annotation
   * representation
   * @param keyInfo
   * @param signature
   * @param annotation
   * @return
   * @throws AnnotatorException
   */
  protected void verifySignature(KeyInfo keyInfo, SignProvider signature, Annotation src) throws 
      AnnotatorException {

    try {
      byte[] verifiable = src.getSignature().getBytes();
      src.setSignature("");
      signature.verify(keyInfo, src.toJson().getBytes(), verifiable); 
    } catch (SignException e) {
      throw new AnnotatorException("cannot verify signature.", e);
    }
  }
}
