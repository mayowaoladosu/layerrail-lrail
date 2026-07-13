load("@lrail/v1/helpers.star", "install")
def build(base, cache_mount):
    return install(base = base, argv = ["bundle", "install"], mounts = [cache_mount], network = "packages", env = {"RAILS_ENV": "production"})
