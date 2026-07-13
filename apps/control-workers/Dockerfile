FROM ruby:3.4.10-bookworm@sha256:e46ac468c9e87ff9209709c5b73ac689688ee82839e2a18af33d14d3577d1340 AS base

ENV BUNDLE_PATH=/usr/local/bundle \
    LANG=C.UTF-8

WORKDIR /app

FROM base AS production-dependencies

ENV BUNDLE_DEPLOYMENT=true \
    BUNDLE_WITHOUT=development:test

COPY Gemfile Gemfile.lock ./
RUN bundle install --jobs 4 --retry 3

FROM base AS test

COPY Gemfile Gemfile.lock ./
RUN bundle install --jobs 4 --retry 3
COPY .rubocop.yml Rakefile ./
COPY lib ./lib
COPY bin ./bin
COPY test ./test
CMD ["bundle", "exec", "rake", "test"]

FROM base AS runtime

ENV BUNDLE_DEPLOYMENT=true \
    BUNDLE_WITHOUT=development:test

RUN groupadd --system --gid 10001 lrail \
    && useradd --system --uid 10001 --gid lrail --home-dir /app --shell /usr/sbin/nologin lrail

COPY --from=production-dependencies /usr/local/bundle /usr/local/bundle
COPY --chown=lrail:lrail Gemfile Gemfile.lock ./
COPY --chown=lrail:lrail lib ./lib
COPY --chown=lrail:lrail bin ./bin

USER 10001:10001

ENTRYPOINT ["bundle", "exec", "ruby", "-Ilib"]
CMD ["bin/worker"]
