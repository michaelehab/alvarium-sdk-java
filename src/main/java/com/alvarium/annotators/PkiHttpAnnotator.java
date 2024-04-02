
/*******************************************************************************
 * Copyright 2022 Dell Inc.
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
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.file.Paths;
import java.time.Instant;
import java.nio.file.Path;

import com.alvarium.SdkInfo;
import com.alvarium.annotators.http.ParseResult;
import com.alvarium.annotators.http.ParseResultException;
import com.alvarium.contracts.Annotation;
import com.alvarium.contracts.AnnotationType;
import com.alvarium.hash.HashProvider;
import com.alvarium.hash.HashType;
import com.alvarium.sign.KeyInfo;
import com.alvarium.sign.SignException;
import com.alvarium.sign.SignProvider;
import com.alvarium.sign.SignType;
import com.alvarium.utils.PropertyBag;

import org.apache.http.client.methods.HttpUriRequest;
import org.apache.logging.log4j.Logger;

class PkiHttpAnnotator extends AbstractAnnotator implements Annotator {
  private final HashProvider hash;
  private final SignProvider signature;
  private final HashType hashType;
  private final AnnotationType kind;
  private final KeyInfo privateKey;
  private final KeyInfo publicKey;

  protected PkiHttpAnnotator(SdkInfo cfg, HashProvider hash, SignProvider signature, Logger logger) {
    super(logger);
    this.hash = hash;
    this.hashType = cfg.getHash().getType();
    this.kind = AnnotationType.PKIHttp;
    this.signature = signature;
    this.privateKey = cfg.getSignature().getPrivateKey();
    this.publicKey = cfg.getSignature().getPublicKey();
  }

  public Annotation execute(PropertyBag ctx, byte[] data) throws AnnotatorException {
    final String key = hash.derive(data);

    HttpUriRequest request;
    try {
      request = ctx.getProperty(AnnotationType.PKIHttp.name(), HttpUriRequest.class);
    } catch (IllegalArgumentException e) {
      throw new AnnotatorException(String.format("Property %s not found", AnnotationType.PKIHttp.name()));
    }
    ParseResult parsed; 
    try {
      parsed = new ParseResult(request);
    } catch (URISyntaxException e) {
      throw new AnnotatorException("Invalid request URI", e);
    } catch (ParseResultException e) {
      throw new AnnotatorException("Error parsing the request", e);
    }
    final Signable signable = new Signable(parsed.getSeed(), parsed.getSignature());

    // Use the parsed request to obtain the key name and type we should use to
    // validate the signature
    
    Path path = Paths.get(this.publicKey.getPath());
    Path directory = path.getParent();
    String publicKeyPath = String.join("/", directory.toString(), parsed.getKeyid());
    
    SignType alg;
    try {
      alg = SignType.fromString(parsed.getAlgorithm());
    } catch (EnumConstantNotPresentException e) {
      throw new AnnotatorException("Invalid key type " + parsed.getAlgorithm());
    }

    KeyInfo k = new KeyInfo(publicKeyPath, alg);

    String host = "";
    boolean isSatisfied;
    try{
      host = InetAddress.getLocalHost().getHostName();

      try {
        signable.verifySignature(k, signature);
        isSatisfied = true;
      }
      catch (SignException ex) {
        isSatisfied = false;
      }
    } catch (UnknownHostException e) {
      isSatisfied = false;
      this.logger.error("Error during PkiHttpAnnotator execution: ",e);
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
      this.logger.error("Error during PkiHttpAnnotator execution: ",ex);
    }
    return annotation;
  }
}
