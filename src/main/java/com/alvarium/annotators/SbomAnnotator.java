/*******************************************************************************
 * Copyright 2024 Dell Inc.
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
import com.alvarium.annotators.sbom.SbomAnnotatorConfig;
import com.alvarium.annotators.sbom.SbomException;
import com.alvarium.annotators.sbom.SbomProvider;
import com.alvarium.annotators.sbom.SbomProviderFactory;
import com.alvarium.contracts.Annotation;
import com.alvarium.contracts.AnnotationType;
import com.alvarium.hash.HashProvider;
import com.alvarium.hash.HashType;
import com.alvarium.sign.KeyInfo;
import com.alvarium.sign.SignException;
import com.alvarium.sign.SignProvider;
import com.alvarium.utils.PropertyBag;

public class SbomAnnotator extends AbstractAnnotator implements Annotator {
  final SbomAnnotatorConfig sbomCfg;

  private final HashProvider hash;
  private final SignProvider signature;
  private final HashType hashType;
  private final AnnotationType kind;
  private final KeyInfo privateKey;

  protected SbomAnnotator(SbomAnnotatorConfig sbomCfg, SdkInfo cfg, HashProvider hash, SignProvider signature, Logger logger) {
    super(logger);
    this.sbomCfg = sbomCfg;
    this.hash = hash;
    this.hashType = cfg.getHash().getType();
    this.kind = AnnotationType.SBOM;
    this.signature = signature;
    this.privateKey = cfg.getSignature().getPrivateKey();
  }
  
  @Override 
  public Annotation execute(PropertyBag ctx, byte[] data) throws AnnotatorException {
    final String key = hash.derive(data);

    String host = "";
    try{
      host = InetAddress.getLocalHost().getHostName();
    } catch (UnknownHostException e) {
      this.logger.error("Error during SbomAnnotator execution: ",e);
    }
    
    boolean isSatisfied = false;
    try {
      final SbomProvider sbom = new SbomProviderFactory().getProvider(this.sbomCfg, this.logger);
      final String filePath = ctx.getProperty(AnnotationType.SBOM.name(), String.class);
      boolean isValid = sbom.validate(filePath);
      boolean exists = sbom.exists(filePath);
      boolean matchesBuild = sbom.matchesBuild(filePath, ".");
      isSatisfied = isValid && exists && matchesBuild;
    } catch (SbomException e) {
      this.logger.error("Error during SbomAnnotator execution: ", e);
    } catch (Exception e) {
      this.logger.error("Error during SbomAnnotator execution: ", e);
    }
    
    final Annotation annotation = new Annotation(
        key, 
        hashType, 
        host, 
        kind, 
        null, 
        isSatisfied, 
        Instant.now()
    );

    try {
      final String annotationSignature = this.signature.sign(this.privateKey, annotation.toString().getBytes());
      annotation.setSignature(annotationSignature);
    }
    catch (SignException ex) {
      this.logger.error("Error during SbomAnnotator execution: ",ex);
    }
    return annotation;	
  }
}
