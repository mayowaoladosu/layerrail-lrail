FROM ruby:3.4.10-alpine3.23@sha256:aee2f8ad808abff4aecaa1d36340dce22e6b1eb9b88216ed18be4245c4324d9b AS base

ENV BUNDLE_PATH=/usr/local/bundle \
    LANG=C.UTF-8

WORKDIR /app

FROM base AS production-dependencies

ENV BUNDLE_DEPLOYMENT=true \
    BUNDLE_WITHOUT=development:test

RUN apk add --no-cache build-base
COPY Gemfile Gemfile.lock ./
RUN bundle install --jobs 4 --retry 3

FROM base AS test

RUN apk add --no-cache build-base
COPY Gemfile Gemfile.lock ./
RUN bundle install --jobs 4 --retry 3
COPY .rubocop.yml Rakefile ./
COPY lib ./lib
COPY bin ./bin
COPY test ./test
CMD ["bundle", "exec", "rake", "test"]

FROM ruby:3.4.10-alpine3.23@sha256:aee2f8ad808abff4aecaa1d36340dce22e6b1eb9b88216ed18be4245c4324d9b AS runtime

ENV BUNDLE_PATH=/usr/local/bundle \
    LANG=C.UTF-8 \
    BUNDLE_DEPLOYMENT=true \
    BUNDLE_WITHOUT=development:test

WORKDIR /app

RUN addgroup -S -g 10001 lrail \
    && adduser -S -D -H -u 10001 -G lrail lrail

COPY --from=production-dependencies /usr/local/bundle /usr/local/bundle
COPY --chown=lrail:lrail Gemfile Gemfile.lock ./
COPY --chown=lrail:lrail lib ./lib
COPY --chown=lrail:lrail bin ./bin

USER 10001:10001

ENTRYPOINT ["bundle", "exec", "ruby", "-Ilib"]
CMD ["bin/worker"]
