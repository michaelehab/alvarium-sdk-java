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

import org.apache.logging.log4j.Logger;

import com.alvarium.SdkInfo;
import com.alvarium.annotators.sbom.SbomAnnotatorConfig;
import com.alvarium.annotators.vulnerability.VulnerabilityAnnotatorConfig;
import com.alvarium.contracts.AnnotationType;
import com.alvarium.hash.HashProvider;
import com.alvarium.hash.HashProviderFactory;
import com.alvarium.hash.HashTypeException;
import com.alvarium.sign.SignException;
import com.alvarium.sign.SignProvider;
import com.alvarium.sign.SignProviderFactory;

public class AnnotatorFactory {

  public Annotator getAnnotator(AnnotatorConfig cfg, SdkInfo config, Logger logger) throws AnnotatorException {
    final HashProvider hashProvider;
    final SignProvider signProvider;

    try {
      hashProvider = new HashProviderFactory().getProvider(config.getHash().getType());
    }
    catch (HashTypeException ex) {
      throw new AnnotatorException("Invalid hash type", ex);
    }

    // Mock Annotator does not use a sign provider
    if (cfg.getKind().equals(AnnotationType.MOCK)) {
        try {
          MockAnnotatorConfig mockCfg = MockAnnotatorConfig.class.cast(cfg);
          return new MockAnnotator(mockCfg, config, hashProvider);
      } catch(ClassCastException e) {
          throw new AnnotatorException("Invalid annotator config", e);
      }
    }

    try {
      signProvider = new SignProviderFactory().getProvider(config.getSignature().getPrivateKey().getType());
    }
    catch (SignException ex) {
      throw new AnnotatorException("Invalid sign provider", ex);
    }

    switch (cfg.getKind()) {
      case TLS:
        return new TlsAnnotator(config, hashProvider, signProvider, logger);
      case PKI:
        return new PkiAnnotator(config, hashProvider, signProvider, logger);
      case PKIHttp:
        return new PkiHttpAnnotator(config, hashProvider, signProvider, logger);
      case TPM:
        return new TpmAnnotator(config, hashProvider, signProvider, logger);
      case SourceCode:
        return new SourceCodeAnnotator(config, hashProvider, signProvider, logger);
      case CHECKSUM:
        return new ChecksumAnnotator(config, hashProvider, signProvider, logger);
      case VULNERABILITY:
        VulnerabilityAnnotatorConfig vulnCfg = VulnerabilityAnnotatorConfig.class.cast(cfg);
        return new VulnerabilityAnnotator(vulnCfg, config, hashProvider, signProvider, logger);
      case SOURCE:
        return new SourceAnnotator(config, hashProvider, signProvider, logger);
      case SBOM:
        final SbomAnnotatorConfig sbomCfg = SbomAnnotatorConfig.class.cast(cfg);
        return new SbomAnnotator(sbomCfg, config, hashProvider, signProvider, logger);
      default:
        throw new AnnotatorException("Annotator type is not supported");
    }
  }
}
