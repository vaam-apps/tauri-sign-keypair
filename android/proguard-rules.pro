# The plugin class and its @Command methods are reached by reflection from
# Tauri's PluginManager, so R8 cannot see any reference to them and would strip
# them from a release build. The symptom is "No command generateKey found",
# only in release, only on a minified app.
-keep class app.vaam.signkeypair.** { *; }
