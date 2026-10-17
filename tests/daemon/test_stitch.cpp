// The automation-stitch operations: names, marker, order, and that every attribute exists in the
// FortiOS 7.4.8 schema. Checked twice: against the engine's catalog (forti-api's compiled 7.4.8
// models, always available) and, when meson finds forti-api's schema snapshot (a co-development
// checkout), against the snapshot's option lists and sizes too.

#include "support.hpp"

#include <events.hpp>
#include <stitch.hpp>

#include <forti/engine/catalog.hpp>

#include <algorithm>
#include <cstdlib>

namespace fph::daemon::test {

    using json = nlohmann::json;

    namespace {

        WebhookTarget target() {
            WebhookTarget t;
            t.host = "192.0.2.10";
            return t;
        }

        // Every key of `object` is an attribute of `fields`; nested tables recurse into children.
        void expect_in_schema(const json& object, const std::vector<forti::engine::FieldInfo>& fields, const std::string& where) {
            for (const auto& [key, value]: object.items()) {
                auto it = std::ranges::find(fields, key, &forti::engine::FieldInfo::name);
                ASSERT_NE(it, fields.end()) << where << ": no attribute \"" << key << "\" in the 7.4.8 schema";
                EXPECT_FALSE(it->read_only) << where << "." << key;
                if (value.is_array())
                    for (const auto& entry: value) expect_in_schema(entry, it->children, where + "." + key);
            }
        }

        // The snapshot's view: option values, string sizes, integer ranges.
        void expect_snapshot(const json& object, const json& children, const std::string& where) {
            for (const auto& [key, value]: object.items()) {
                ASSERT_TRUE(children.contains(key)) << where << "." << key;
                const auto& spec = children[key];
                if (spec.contains("options")) {
                    bool found = false;
                    for (const auto& option: spec["options"]) found = found || option["name"] == value;
                    EXPECT_TRUE(found) << where << "." << key << " = " << value;
                }
                if (value.is_string() && spec.contains("size")) {
                    EXPECT_LE(value.get<std::string>().size(), spec["size"].get<std::size_t>()) << where << "." << key;
                }
                if (value.is_number_integer() && spec.contains("max-value")) {
                    EXPECT_LE(value.get<long long>(), spec["max-value"].get<long long>()) << where << "." << key;
                }
                if (value.is_array())
                    for (const auto& entry: value) expect_snapshot(entry, spec["children"], where + "." + key);
            }
        }

    }  // namespace

    TEST(Stitch, CreatesTriggerActionStitchInOrder) {
        auto ops = stitch_create_operations(target(), token);
        ASSERT_EQ(ops.size(), 3u);
        EXPECT_EQ(ops[0]["resource"], "system/automation-trigger");
        EXPECT_EQ(ops[1]["resource"], "system/automation-action");
        EXPECT_EQ(ops[2]["resource"], "system/automation-stitch");
        for (const auto& op: ops) {
            EXPECT_EQ(op["op"], "create");
            EXPECT_TRUE(op["object"]["name"].get<std::string>().starts_with("fp-"));
            EXPECT_EQ(op["object"]["description"], "managed by forti-pihole");
            EXPECT_TRUE(is_managed(op["object"]));
        }
        const auto& trigger = ops[0]["object"];
        EXPECT_EQ(trigger["name"], "fp-sync-event");
        EXPECT_EQ(trigger["event-type"], "config-change");
        EXPECT_EQ(trigger["trigger-type"], "event-based");

        const auto& action = ops[1]["object"];
        EXPECT_EQ(action["name"], "fp-sync-webhook");
        EXPECT_EQ(action["action-type"], "webhook");
        EXPECT_EQ(action["protocol"], "http");
        EXPECT_EQ(action["method"], "post");
        EXPECT_EQ(action["port"], 8735);
        EXPECT_EQ(action["uri"], "192.0.2.10/v1/fortigate/events");
        EXPECT_FALSE(action.contains("verify-host-cert"));   // http
        ASSERT_EQ(action["http-headers"].size(), 2u);
        EXPECT_EQ(action["http-headers"][0]["key"], "Authorization");
        EXPECT_EQ(action["http-headers"][0]["value"], std::string("Bearer ") + token);
        EXPECT_EQ(action["http-headers"][1]["key"], "Content-Type");
        EXPECT_EQ(action["http-body"], webhook_body());

        const auto& stitch = ops[2]["object"];
        EXPECT_EQ(stitch["name"], "fp-sync");
        EXPECT_EQ(stitch["trigger"], "fp-sync-event");
        EXPECT_EQ(stitch["status"], "enable");
        ASSERT_EQ(stitch["actions"].size(), 1u);
        EXPECT_EQ(stitch["actions"][0]["action"], "fp-sync-webhook");
        EXPECT_EQ(stitch["actions"][0]["required"], "enable");
    }

    TEST(Stitch, BodyTemplateIsJsonOfLogVariablesTheReceiverReads) {
        auto body = webhook_body();
        auto parsed = json::parse(body);   // valid JSON as installed (before substitution)
        for (const char* field: {"logid", "eventtime", "vd", "user", "ui", "action", "cfgtid", "cfgpath", "cfgobj", "logdesc"})
            EXPECT_EQ(parsed[field], std::string("%%log.") + field + "%%") << field;
        EXPECT_FALSE(parsed.contains("cfgattr"));
        EXPECT_LE(body.size(), 4095u);
        // What the receiver makes of it once FortiOS has substituted the values.
        std::string substituted = body;
        auto replace = [&](std::string_view from, std::string_view to) {
            substituted.replace(substituted.find(from), from.size(), to);
        };
        replace("%%log.cfgpath%%", "firewall.addrgrp");
        replace("%%log.cfgobj%%", "fp-seg-iot");
        replace("%%log.action%%", "Edit");
        auto event = parse_event(substituted);
        EXPECT_TRUE(event.structured);
        EXPECT_EQ(event.resource(), "firewall/addrgrp");
        EXPECT_EQ(event.cfgobj, "fp-seg-iot");
        EXPECT_EQ(event.user, "");   // still a %%variable%%: carries nothing
    }

    TEST(Stitch, HttpsAndOptions) {
        auto t = target();
        t.protocol = "https";
        t.port = 443;
        t.verify_host_cert = false;
        t.host = "2001:db8::10";
        auto ops = stitch_create_operations(t, token, "lab-");
        const auto& action = ops[1]["object"];
        EXPECT_EQ(action["name"], "lab-sync-webhook");
        EXPECT_EQ(action["uri"], "[2001:db8::10]/v1/fortigate/events");
        EXPECT_EQ(action["verify-host-cert"], "disable");
    }

    TEST(Stitch, RefusesInvalidInput) {
        auto t = target();
        EXPECT_THROW(stitch_create_operations(t, "short"), StitchError);
        EXPECT_THROW(stitch_create_operations(t, std::string(token) + "\r\nX-Injected: 1"), StitchError);
        EXPECT_THROW(stitch_create_operations(t, token, "x"), StitchError);
        EXPECT_THROW(stitch_create_operations(t, token, std::string(25, 'p')), StitchError);
        t.protocol = "ftp";
        EXPECT_THROW(stitch_create_operations(t, token), StitchError);
        t = target();
        t.host = "http://192.0.2.10";
        EXPECT_THROW(stitch_create_operations(t, token), StitchError);
        t.host = "192.0.2.10/evil";
        EXPECT_THROW(stitch_create_operations(t, token), StitchError);
        t = target();
        t.port = 0;
        EXPECT_THROW(stitch_create_operations(t, token), StitchError);
        t = target();
        t.path = "/a b";
        EXPECT_THROW(stitch_create_operations(t, token), StitchError);
        // The longest allowed prefix still fits FortiOS's 35-character names.
        auto names = stitch_names(std::string(24, 'p'));
        EXPECT_LE(names.trigger.size(), 35u);
        EXPECT_LE(names.stitch.size(), 35u);
    }

    TEST(Stitch, DeleteIsTheInverseInReverseOrder) {
        auto ops = stitch_delete_operations();
        ASSERT_EQ(ops.size(), 3u);
        EXPECT_EQ(ops[0], json({{"op", "delete"}, {"resource", "system/automation-stitch"}, {"key", "fp-sync"}}));
        EXPECT_EQ(ops[1], json({{"op", "delete"}, {"resource", "system/automation-action"}, {"key", "fp-sync-webhook"}}));
        EXPECT_EQ(ops[2], json({{"op", "delete"}, {"resource", "system/automation-trigger"}, {"key", "fp-sync-event"}}));
        auto created = stitch_create_operations(target(), token);
        for (std::size_t i = 0; i < 3; ++i) {
            EXPECT_EQ(ops[i]["resource"], created[2 - i]["resource"]);
            EXPECT_EQ(ops[i]["key"], created[2 - i]["object"]["name"]);
        }
        EXPECT_FALSE(is_managed(json{{"name", "fp-sync"}, {"description", "an admin's stitch"}}));
        EXPECT_FALSE(is_managed(json{{"name", "fp-sync"}}));
    }

    TEST(Stitch, AttributesExistInTheCompiledSchema) {
        const auto& catalog = forti::engine::Catalog::instance();
        for (const auto& op: stitch_create_operations(target(), token)) {
            const auto* resource = catalog.find(op["resource"].get<std::string>());
            ASSERT_NE(resource, nullptr) << op["resource"];
            EXPECT_EQ(resource->kind, forti::engine::Kind::table);
            EXPECT_EQ(resource->key, "name");
            expect_in_schema(op["object"], resource->fields(), op["resource"].get<std::string>());
        }
    }

    TEST(Stitch, MatchesTheSchemaSnapshot) {
        const char* dir = std::getenv("FPHD_SCHEMA_DIR");
        if (!dir || !*dir) GTEST_SKIP() << "forti-api's schema snapshot is not available in this build";
        auto t = target();
        t.protocol = "https";   // covers verify-host-cert as well
        for (const auto& op: stitch_create_operations(t, token)) {
            auto name = op["resource"].get<std::string>().substr(std::string("system/").size());
            auto text = read_file(fs::path(dir) / (name + ".json"));
            ASSERT_FALSE(text.empty()) << name;
            auto schema = json::parse(text);
            EXPECT_EQ(schema["mkey"], "name");
            expect_snapshot(op["object"], schema["children"], name);
        }
    }

}  // namespace fph::daemon::test
