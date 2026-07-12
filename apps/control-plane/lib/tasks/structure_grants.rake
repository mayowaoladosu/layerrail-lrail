Rake::Task["db:schema:dump"].enhance do
  structure_path = Rails.root.join("db", "structure.sql")
  grants_path = Rails.root.join("db", "runtime_grants.sql")
  marker = "-- LRAIL_RUNTIME_GRANTS_BEGIN"
  structure = structure_path.read.sub(/\n#{Regexp.escape(marker)}.*\z/m, "")
  structure_path.write("#{structure.rstrip}\n\n#{marker}\n#{grants_path.read.rstrip}\n")
end
