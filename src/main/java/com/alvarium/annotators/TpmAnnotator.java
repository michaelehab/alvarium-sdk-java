
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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
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

class TpmAnnotator extends AbstractAnnotator implements Annotator {
  private final HashProvider hash;
  private final SignProvider signature;
  private final HashType hashType;
  private final AnnotationType kind;
  private final KeyInfo privateKey;
  private final String directTpmPath = "/dev/tpm0";
  private final String tpmKernelManagedPath = "/dev/tpmrm0";

  protected TpmAnnotator(SdkInfo cfg, HashProvider hash, SignProvider signature, Logger logger) {
    super(logger);
    this.hash = hash;
    this.hashType = cfg.getHash().getType();
    this.kind = AnnotationType.TPM;
    this.signature = signature;
    this.privateKey = cfg.getSignature().getPrivateKey();
  }

  public Annotation execute(PropertyBag ctx, byte[] data) throws AnnotatorException {
    
    final String key = hash.derive(data);

    String host = "";
    boolean isSatisfied;
    try {
      host = InetAddress.getLocalHost().getHostName();
      // Checks whether the TPM driver is accessible through the kernel resource manager, and if that 
      // failes, checks if the TPM driver can be accessed directly
      isSatisfied = checkTpmExists(this.tpmKernelManagedPath) ||
        checkTpmExists(this.directTpmPath);
    } catch (UnknownHostException | AnnotatorException e) {
      isSatisfied = false;
      this.logger.error("Error during TpmAnnotator execution: ",e);
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
      this.logger.error("Error during TpmAnnotator execution: ",ex);
    }
    return annotation;
  }

  /**
   * Checks whether the TPM driver exists (can be accessed) or not, this check was found on the 
   * Microsoft TSS.MSR repository found here 
   * https://github.com/microsoft/TSS.MSR/blob/d715b/TSS.Java/src/tss/TpmDeviceLinux.java
   * 
   * @param devName the tpm path
   * @return True if TPM found, false otherwise
   * @throws AnnotatorException
   */
  private Boolean checkTpmExists(String devName) throws AnnotatorException {
    final RandomAccessFile devTpm;
    final File devTpm0 = new File(devName);
    if (!devTpm0.exists()) {
      return false;
    }
    try {
        devTpm = new RandomAccessFile(devName, "rwd");
        devTpm.close();
        return true;
    } catch (FileNotFoundException e) {
        return false;
    } catch (IOException e) {
      throw new AnnotatorException("Could not close tpm file", e);
    }
  }
}
