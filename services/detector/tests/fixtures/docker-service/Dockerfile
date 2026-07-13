FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY app /app
EXPOSE 8080
HEALTHCHECK CMD ["/app", "healthcheck"]
ENTRYPOINT ["/app"]
CMD ["serve"]
