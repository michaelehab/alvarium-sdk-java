
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


import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Map;
import org.apache.logging.log4j.Logger;

import com.alvarium.contracts.Annotation;
import com.alvarium.contracts.AnnotationType;
import com.alvarium.contracts.LayerType;
import com.alvarium.hash.HashProvider;
import com.alvarium.hash.HashProviderFactory;
import com.alvarium.hash.HashType;
import com.alvarium.hash.HashTypeException;
import com.alvarium.sign.SignatureInfo;
import com.alvarium.utils.PropertyBag;
import com.alvarium.tag.TagManager;

import com.alvarium.annotators.sourcecode.CheckSumCalculator;

class SourceCodeAnnotator extends AbstractAnnotator implements Annotator {

    private final HashType hash;
    private final AnnotationType kind;
    private final SignatureInfo signature;
    private final LayerType layer;
    private final TagManager tagManager;
    private final CheckSumCalculator checkSumCalculator;

    private HashProvider hashProvider;

    protected SourceCodeAnnotator(HashType hash, SignatureInfo signature, Logger logger, LayerType layer) throws AnnotatorException {
        super(logger);
        this.hash = hash;
        this.kind = AnnotationType.SourceCode;
        this.signature = signature;
        this.layer = layer;
        this.tagManager = new TagManager(layer);
        this.checkSumCalculator = new CheckSumCalculator(hash);
    }

    // File (git working directory) is to be passed in the ctx bag
    // expects commitHash and directory from ctx
    @Override
    public Annotation execute(PropertyBag ctx, byte[] data) throws AnnotatorException {
        this.initHashProvider(this.hash);
        final String key = this.hashProvider.derive(data);

        final SourceCodeAnnotatorProps props = ctx.getProperty(
            AnnotationType.SourceCode.name(),
            SourceCodeAnnotatorProps.class
        );

        String host = "";
        boolean isSatisfied;
        try{
            host = InetAddress.getLocalHost().getHostName();
            final String checksum = this.readChecksum(props.getChecksumPath());
            final String generatedChecksum = checkSumCalculator.generateChecksum(props.getSourceCodePath());
            isSatisfied = generatedChecksum.equals(checksum);
        } catch (UnknownHostException | AnnotatorException e) {
            isSatisfied = false;
            this.logger.error("Error during SourceCodeAnnotator execution: ",e);
        }

        final Annotation annotation = new Annotation(
            key,
            hash,
            host,
            layer,
            kind,
            null,
            isSatisfied,
            Instant.now()
        );
        
        annotation.setTag(tagManager.getTagValue(ctx.getProperty("overrides", Map.class)));
        // annotation.setTag(ctx.getProperty("CiCdTag", String.class));

        final String annotationSignature = super.signAnnotation(signature.getPrivateKey(), annotation);
        annotation.setSignature(annotationSignature);
        return annotation;
    }

    private String readChecksum(String path) throws AnnotatorException {
        try {
            final Path p = Paths.get(path);
            return Files.readString(p);
        } catch (IOException e) {
            throw new AnnotatorException("Failed to read file, could not validate checksum", e);
        } catch (SecurityException e) {
            throw new AnnotatorException(
                "Insufficient permission to access file, could not validate checksum", 
                e
            );
        } catch (OutOfMemoryError e) {
            throw new AnnotatorException(
                "Failed to read file due to size larger than 2GB, could not validate checksum " + e
            );
        } catch (Exception e) {
            throw new AnnotatorException("Could not validate checksum");
        }
    }

    /**
     *  Initializes the hash provider used to hash the source code 
     * @return HashProvider
     * @throws AnnotatorException - If hashing algorithm not found, 
     * or if an unknown exception was thrown
     */
    private final void initHashProvider(HashType hashType) throws AnnotatorException {
        try {
             this.hashProvider = new HashProviderFactory().getProvider(hashType);
        } catch (HashTypeException e) {
            throw new AnnotatorException("Hashing algorithm not found, could not hash data or generate checksum", e);
        } catch (Exception e) {
            throw new AnnotatorException("Could not hash data or generate checksum", e);
        }
    }
}
