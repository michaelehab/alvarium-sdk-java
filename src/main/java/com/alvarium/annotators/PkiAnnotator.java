
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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;

import org.apache.logging.log4j.Logger;

import com.alvarium.SdkInfo;
import com.alvarium.contracts.Annotation;
import com.alvarium.contracts.AnnotationType;
import com.alvarium.hash.HashProvider;
import com.alvarium.hash.HashType;
import com.alvarium.sign.KeyInfo;
import com.alvarium.sign.SignException;
import com.alvarium.sign.SignProvider;
import com.alvarium.utils.PropertyBag;

class PkiAnnotator extends AbstractAnnotator implements Annotator {
  private final HashProvider hash;
  private final SignProvider signature;
  private final HashType hashType;
  private final AnnotationType kind;
  private final KeyInfo privateKey;
  private final KeyInfo publicKey;

  protected PkiAnnotator(SdkInfo cfg, HashProvider hash, SignProvider signature, Logger logger) {
    super(logger);
    this.hash = hash;
    this.hashType = cfg.getHash().getType();
    this.kind = AnnotationType.PKI;
    this.signature = signature;
    this.privateKey = cfg.getSignature().getPrivateKey();
    this.publicKey = cfg.getSignature().getPublicKey();
    this.logger.debug("Public key is ", this.publicKey.getPath());
  }

  public Annotation execute(PropertyBag ctx, byte[] data) throws AnnotatorException {
    final String key = hash.derive(data);

    final Signable signable = Signable.fromJson(new String(data));

    String host = "";
    boolean isSatisfied;
    try {
      host = InetAddress.getLocalHost().getHostName();
      try {
        signable.verifySignature(this.publicKey, this.signature);
        isSatisfied = true;
      }
      catch (SignException ex) {
        this.logger.error("Signable Raised a SignException when given, " + this.publicKey.getPath().toString() + ", and, "+  this.signature.toString());
        isSatisfied = false;
      }
    } catch (UnknownHostException e) {
      isSatisfied = false;
      this.logger.error("Error during PkiAnnotator execution: ",e);
    } 

    final Annotation annotation = new Annotation(
        key, 
        hashType, 
        host, 
        kind, 
        null, 
        isSatisfied, 
        Instant.now());

    try {
      final String annotationSignature = this.signature.sign(this.privateKey, annotation.toString().getBytes());
      annotation.setSignature(annotationSignature);
    }
    catch (SignException ex) {
      this.logger.error("Error during PkiAnnotator execution: ",ex);
    }

    return annotation;

  }
  
}
