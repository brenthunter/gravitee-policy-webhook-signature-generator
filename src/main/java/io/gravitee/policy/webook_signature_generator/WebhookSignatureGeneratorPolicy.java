/**
 * Copyright (C) 2025 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.webook_signature_generator;

import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.el.EvaluableRequest;
import io.gravitee.gateway.api.el.EvaluableResponse;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.api.stream.BufferedReadWriteStream;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.gateway.api.stream.SimpleReadWriteStream;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
//import io.gravitee.gateway.reactive.api.context.HttpExecutionContext;
//import io.gravitee.gateway.reactive.api.context.MessageExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpBaseExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpMessageExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
//import io.gravitee.gateway.reactive.api.context.kafka.KafkaExecutionContext;
//import io.gravitee.gateway.reactive.api.context.kafka.KafkaMessageExecutionContext;
import io.gravitee.gateway.reactive.api.message.Message;
//import io.gravitee.gateway.reactive.api.message.kafka.KafkaMessage;
import io.gravitee.gateway.reactive.api.policy.Policy;
import io.gravitee.gateway.reactive.api.policy.http.HttpPolicy;
//import io.gravitee.gateway.reactive.api.policy.kafka.KafkaPolicy;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
//import io.gravitee.policy.api.annotations.OnResponse;
//import io.gravitee.policy.api.annotations.OnResponseContent;
import io.gravitee.policy.webook_signature_generator.configuration.SchemeTypeConfiguration;
import io.gravitee.policy.webook_signature_generator.configuration.WebhookSignatureGeneratorPolicyConfiguration;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Flowable;
import io.reactivex.rxjava3.core.Maybe;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;

/**
 * @author Brent HUNTER (brent.hunter at graviteesource.com)
 * @author GraviteeSource Team
 */
@Slf4j
//public class WebhookSignatureGeneratorPolicy implements HttpPolicy, KafkaPolicy {
public class WebhookSignatureGeneratorPolicy implements HttpPolicy {

    private static final String WEBHOOK_SIGNATURE_ERROR = "WEBHOOK_SIGNATURE_ERROR";
    private static final String WEBHOOK_SIGNATURE_INVALID_SIGNATURE = "WEBHOOK_SIGNATURE_INVALID_SIGNATURE";
    private static final String WEBHOOK_SIGNATURE_NOT_FOUND = "WEBHOOK_SIGNATURE_NOT_FOUND";
    private static final String WEBHOOK_SIGNATURE_NOT_BASE64 = "WEBHOOK_SIGNATURE_NOT_BASE64";
    private static final String WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID = "WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID";

    /**
     * Policy configuration
     */
    private final WebhookSignatureGeneratorPolicyConfiguration configuration;

    public WebhookSignatureGeneratorPolicy(final WebhookSignatureGeneratorPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public String id() {
        return "webhook-signature-generator";
    }

    // HTTP RESPONSE
    // **************
    @Override
    public Completable onResponse(HttpPlainExecutionContext ctx) {
        return ctx
            .response()
            .body()
            .flatMapCompletable(buffer -> generateSignatureforHTTP(ctx, ctx.response().headers(), buffer))
            .onErrorResumeWith(ctx.interruptWith(new ExecutionFailure(500).key(WEBHOOK_SIGNATURE_ERROR).message("Unable to process Signature Generator in HTTP!")));
    }

    private Completable generateSignatureforHTTP(final HttpPlainExecutionContext ctx, final HttpHeaders httpHeaders, final Buffer buffer) {
        log.info("Executing WebhookSignatureGeneratorPolicy (in onResponse context)...");

        String secret = ctx.getTemplateEngine().getValue(configuration.getSecret(), String.class);
        String algorithm = configuration.getAlgorithm();
        //String messageContent = message.content().toString();
        List<String> addedHeaders = null;
        String headersDelimiter = null;
        String httpBody = buffer.toString();

        log.debug("Config> HTTPBody: {}", httpBody);

        log.debug("Config> Does the Signature validation require additional HTTP headers?: {}", configuration.getSchemeType().isEnabled()); // true|false
        if (configuration.getSchemeType().isEnabled()) {
            addedHeaders = new ArrayList<>(configuration.getSchemeType().getHeaders());

            headersDelimiter = configuration.getSchemeType().getHeadersDelimiter();
            log.debug("Config> headersDelimiter: {}", headersDelimiter);

            if (addedHeaders.size() > 0) {
                int i = 0;
                String tmpData = "";
                while (i < addedHeaders.size()) {
                    log.debug("Config> Prefixing HTTP header '{}' ({}) to HTTP Body", addedHeaders.get(i), ctx.response().headers().get(addedHeaders.get(i)));
                    if (ctx.response().headers().get(addedHeaders.get(i)) == null) {
                        return ctx.interruptWith(new ExecutionFailure(500).key(WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID).message("A specified header value is invalid or missing!"));
                    } else {
                        tmpData += ctx.response().headers().get(addedHeaders.get(i)) + headersDelimiter;
                    }
                    i++;
                }
                httpBody = tmpData + httpBody;
            } else {
                return ctx.interruptWith(new ExecutionFailure(500).key(WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID).message("A specified header value is invalid or missing!"));
            }

            log.debug("HTTPBody (prepended with additional header values): {}", httpBody);
        }

        //Generate HMAC Signature
        String mySignature = generateHmacSignature(httpBody, secret, algorithm);

        return addSignatureToHeader(ctx.getTemplateEngine(), httpHeaders, mySignature)
            .onErrorResumeWith(ctx.interruptWith(new ExecutionFailure(500).key(WEBHOOK_SIGNATURE_ERROR).message("Unable to process Signature Generator in HTTP!")));
    }

    // MESSAGE RESPONSE
    // ****************
    @Override
    public Completable onMessageResponse(HttpMessageExecutionContext ctx) {
        return ctx.response().onMessage(message -> generateSignatureForMessage(ctx, message));
    }

    private Maybe<Message> generateSignatureForMessage(final HttpMessageExecutionContext ctx, final Message message) {
        log.info("Executing WebhookSignatureGeneratorPolicy (in onMessageResponse context)...");

        String secret = ctx.getTemplateEngine().getValue(configuration.getSecret(), String.class);
        String algorithm = configuration.getAlgorithm();
        String messageContent = message.content().toString();
        List<String> addedHeaders = null;
        String headersDelimiter = null;

        log.debug("Config> messageContent: {}", messageContent);

        log.debug("Config> Does the Signature validation require additional Message headers?: {}", configuration.getSchemeType().isEnabled()); // true|false
        if (configuration.getSchemeType().isEnabled()) {
            addedHeaders = new ArrayList<>(configuration.getSchemeType().getHeaders());

            headersDelimiter = configuration.getSchemeType().getHeadersDelimiter();
            log.debug("Config> headersDelimiter: {}", headersDelimiter);

            if (addedHeaders.size() > 0) {
                int i = 0;
                String tmpData = "";
                while (i < addedHeaders.size()) {
                    log.debug("Config> Prefixing HTTP/Message header '{}' ({}) to Message Content", addedHeaders.get(i), message.headers().get(addedHeaders.get(i)));
                    if (message.headers().get(addedHeaders.get(i)) == null) {
                        return ctx.interruptMessageWith(
                            new ExecutionFailure(500).key(WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID).message("A specified header value is invalid or missing!")
                        );
                    } else {
                        tmpData += message.headers().get(addedHeaders.get(i)) + headersDelimiter;
                    }
                    i++;
                }
                messageContent = tmpData + messageContent;
            } else {
                return ctx.interruptMessageWith(new ExecutionFailure(500).key(WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID).message("A specified header value is invalid or missing!"));
            }

            log.debug("messageContent (prepended with additional header values): {}", messageContent);
        }

        //Generate HMAC Signature
        String mySignature = generateHmacSignature(messageContent, secret, algorithm);

        return addSignatureToHeader(ctx.getTemplateEngine(message), message.headers(), mySignature)
            .andThen(Maybe.just(message))
            .onErrorResumeWith(ctx.interruptMessageWith(new ExecutionFailure(500).key(WEBHOOK_SIGNATURE_ERROR).message("Unable to process Signature Generator in Message!")));
    }

    // SUPPORTING CODE
    // ***************

    private Completable addSignatureToHeader(final TemplateEngine templateEngine, final HttpHeaders httpHeaders, final String signature) {
        log.debug("Setting '{}' HTTP Header to '{}'", configuration.getTargetSignatureHeader(), signature);
        return Completable.fromRunnable(() -> httpHeaders.set(configuration.getTargetSignatureHeader(), signature));
    }

    // Method to generate HMAC signature
    private String generateHmacSignature(String data, String secretKey, String algorithm) {
        try {
            // Create a SecretKeySpec from the key
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), algorithm);

            // Initialize the Mac instance with the specified algorithm
            Mac mac = Mac.getInstance(algorithm);
            mac.init(secretKeySpec);

            // Generate the HMAC hash of the data
            byte[] hmacHash = mac.doFinal(data.getBytes("UTF-8"));

            log.debug("Generated HMAC signature: {}", Base64.getEncoder().encodeToString(hmacHash));

            // Return the Base64 encoded HMAC signature
            return Base64.getEncoder().encodeToString(hmacHash);
        } catch (Exception ex) {
            log.error("Exception occurred while generating HMAC signature!");
            log.error(ex.getMessage());
            //request.metrics().setMessage(ex.getMessage());
            return null;
        }
    }
}
