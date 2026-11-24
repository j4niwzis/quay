// SPDX-License-Identifier: AGPL-3.0-only
// quay.chat -- simplex-chat's messages, typed: what a connection's message
// body carries (quay.connection's event::message, decompressed by
// quay.compression), read once into types through knot, and the messages
// quay sends, written from them.
//
// A chat message is {"v":"1-22","msgId":...,"event":"x.msg.new","params":{...}};
// its params are chosen by its event, those quay understands typed and the
// rest kept as their JSON text, never looked inside. An uncompressed body
// is one message or, starting with '[', a JSON array of them.
export module quay.chat;

import std;
import splice;
import knot;
import quay.bytes;
import quay.compression;

export namespace quay::chat {

// The chat protocol's versions quay speaks, as simplex-chat writes them.
inline constexpr std::string_view versions = "1-22";

// ---- what messages say ------------------------------------------------------

struct profile {
  std::string display_name;
  std::string full_name;
  std::optional<std::string> image;          // a data: URI
  std::optional<std::string> short_descr;
  std::optional<knot::raw> preferences;      // kept as it came
  std::optional<std::string> peer_type;      // "bot", where it is one
};
consteval auto json_schema(knot::type<profile>) {
  return knot::schema<profile>()
      .member<"display_name">(knot::key("displayName"))
      .member<"full_name">(knot::key("fullName"))
      .member<"short_descr">(knot::key("shortDescr"))
      .member<"peer_type">(knot::key("peerType"));
}

// A message's content: its kind by its "type", its text, and the rest of
// what the kind carries kept as it came (a link's preview, an image).
struct content {
  std::string type;
  std::string text;
  std::optional<knot::raw> preview, image, report_reason;
  std::optional<std::int64_t> duration;
};
consteval auto json_schema(knot::type<content>) {
  return knot::schema<content>().member<"report_reason">(knot::key("reason"));
}
namespace kind {
struct text {};
struct link {};
struct image {};
struct video {};
struct voice {};
struct file {};
struct report {};
struct chat {};
struct unknown {};  // a kind quay does not know: its text still shown
}  // namespace kind
using kind_t = spl::variant<kind::text, kind::link, kind::image, kind::video, kind::voice, kind::file, kind::report, kind::chat, kind::unknown>;
// The content's "type", read once into its kind.
inline kind_t kind_of(const content& c) {
  static const std::array<std::pair<std::string_view, kind_t>, 8> kinds{{{"text", kind::text{}},
                                                                             {"link", kind::link{}},
                                                                             {"image", kind::image{}},
                                                                             {"video", kind::video{}},
                                                                             {"voice", kind::voice{}},
                                                                             {"file", kind::file{}},
                                                                             {"report", kind::report{}},
                                                                             {"chat", kind::chat{}}}};
  const auto found = std::ranges::find(kinds, std::string_view(c.type), &std::pair<std::string_view, kind_t>::first);
  return found == kinds.end() ? kind_t(kind::unknown{}) : found->second;
}
inline content text_content(std::string text) { return content{"text", std::move(text), {}, {}, {}, {}}; }

// A file sent through XFTP: its name and size, and its description -- the
// text quay.xfile reads -- in parts, the first one here, the rest in
// x.msg.file.descr messages.
struct file_description_part {
  std::string text;
  std::int64_t part = 0;
  bool complete = false;
};
consteval auto json_schema(knot::type<file_description_part>) {
  return knot::schema<file_description_part>()
      .member<"text">(knot::key("fileDescrText"))
      .member<"part">(knot::key("fileDescrPartNo"))
      .member<"complete">(knot::key("fileDescrComplete"));
}
struct file_invitation {
  std::string file_name;
  std::int64_t file_size = 0;
  std::optional<file_description_part> description;
  std::optional<knot::raw> digest, connection_link, inline_mode;
};
consteval auto json_schema(knot::type<file_invitation>) {
  return knot::schema<file_invitation>()
      .member<"file_name">(knot::key("fileName"))
      .member<"file_size">(knot::key("fileSize"))
      .member<"description">(knot::key("fileDescr"))
      .member<"digest">(knot::key("fileDigest"))
      .member<"connection_link">(knot::key("fileConnReq"))
      .member<"inline_mode">(knot::key("fileInline"));
}

// A reaction: an emoji, or one of simplex-chat's own.
struct reaction {
  std::string type;
  std::optional<std::string> emoji;
};
consteval auto json_schema(knot::type<reaction>) { return knot::schema<reaction>(); }

// ---- groups -------------------------------------------------------------------------

// A member, as the protocol names one: its id (base64) and its role
// ("owner", "admin", "member", ... -- kept as text: what roles allow is
// not decided here).
struct member_id_role {
  std::string member_id;
  std::string member_role;
};
consteval auto json_schema(knot::type<member_id_role>) {
  return knot::schema<member_id_role>().member<"member_id">(knot::key("memberId")).member<"member_role">(knot::key("memberRole"));
}
struct group_profile {
  std::string display_name;
  std::string full_name;
  std::optional<std::string> description, image;
  std::optional<knot::raw> group_preferences;
};
consteval auto json_schema(knot::type<group_profile>) {
  return knot::schema<group_profile>()
      .member<"display_name">(knot::key("displayName"))
      .member<"full_name">(knot::key("fullName"))
      .member<"group_preferences">(knot::key("groupPreferences"));
}
// An invitation to a group: who invites, the member we are to be, the
// invitation link our member connection joins, the group itself.
struct group_invitation {
  member_id_role from_member;
  member_id_role invited_member;
  std::string connection_link;
  chat::group_profile group_profile;
  std::optional<std::string> group_link_id;
  std::optional<std::int64_t> group_size;
};
consteval auto json_schema(knot::type<group_invitation>) {
  return knot::schema<group_invitation>()
      .member<"from_member">(knot::key("fromMember"))
      .member<"invited_member">(knot::key("invitedMember"))
      .member<"connection_link">(knot::key("connRequest"))
      .member<"group_profile">(knot::key("groupProfile"))
      .member<"group_link_id">(knot::key("groupLinkId"))
      .member<"group_size">(knot::key("groupSize"));
}

// ---- the events, each its params ---------------------------------------------

namespace event {
struct info {  // x.info: who the other side is
  chat::profile profile;
};
struct info_probe {  // x.info.probe: a probe, to find the same contact through another connection
  std::string probe;
};
struct info_probe_check {  // x.info.probe.check
  std::string probe_hash;
};
struct info_probe_ok {  // x.info.probe.ok
  std::string probe;
};
struct ok {};  // x.ok
struct message_new {  // x.msg.new
  chat::content content;
  std::optional<knot::raw> quote, parent, forward, mentions;
  std::optional<file_invitation> file;
  std::optional<std::int64_t> ttl;
  std::optional<bool> live;
};
struct message_update {  // x.msg.update
  std::string message_id;
  chat::content content;
  std::optional<std::int64_t> ttl;
  std::optional<bool> live;
};
struct message_delete {  // x.msg.del
  std::string message_id;
  std::optional<std::string> member_id;
};
struct message_react {  // x.msg.react
  std::string message_id;
  std::optional<std::string> member_id;
  chat::reaction reaction;
  bool add = true;
};
struct file_description {  // x.msg.file.descr: a further part of a file's description
  std::string message_id;
  file_description_part description;
};
consteval auto json_schema(knot::type<file_description>) {
  return knot::schema<file_description>()
      .member<"message_id">(knot::key("msgId"))
      .member<"description">(knot::key("fileDescr"))
      .tag("x.msg.file.descr");
}
struct group_invite {  // x.grp.inv
  chat::group_invitation group_invitation;
};
consteval auto json_schema(knot::type<group_invite>) {
  return knot::schema<group_invite>().member<"group_invitation">(knot::key("groupInvitation")).tag("x.grp.inv");
}
struct group_accept {  // x.grp.acpt: the connection info a member joining says
  std::string member_id;
  std::optional<chat::profile> profile;
};
consteval auto json_schema(knot::type<group_accept>) {
  return knot::schema<group_accept>().member<"member_id">(knot::key("memberId")).tag("x.grp.acpt");
}
struct group_member_info {  // x.grp.mem.info: the host's, on our member connection
  std::string member_id;
  chat::profile profile;
};
consteval auto json_schema(knot::type<group_member_info>) {
  return knot::schema<group_member_info>().member<"member_id">(knot::key("memberId")).tag("x.grp.mem.info");
}
struct direct_delete {};  // x.direct.del: the contact deleted us
consteval auto json_schema(knot::type<info>) { return knot::schema<info>().tag("x.info"); }
consteval auto json_schema(knot::type<info_probe>) { return knot::schema<info_probe>().tag("x.info.probe"); }
consteval auto json_schema(knot::type<info_probe_check>) {
  return knot::schema<info_probe_check>().member<"probe_hash">(knot::key("probeHash")).tag("x.info.probe.check");
}
consteval auto json_schema(knot::type<info_probe_ok>) { return knot::schema<info_probe_ok>().tag("x.info.probe.ok"); }
consteval auto json_schema(knot::type<ok>) { return knot::schema<ok>().tag("x.ok"); }
consteval auto json_schema(knot::type<message_new>) { return knot::schema<message_new>().tag("x.msg.new"); }
consteval auto json_schema(knot::type<message_update>) {
  return knot::schema<message_update>().member<"message_id">(knot::key("msgId")).tag("x.msg.update");
}
consteval auto json_schema(knot::type<message_delete>) {
  return knot::schema<message_delete>()
      .member<"message_id">(knot::key("msgId"))
      .member<"member_id">(knot::key("memberId"))
      .tag("x.msg.del");
}
consteval auto json_schema(knot::type<message_react>) {
  return knot::schema<message_react>()
      .member<"message_id">(knot::key("msgId"))
      .member<"member_id">(knot::key("memberId"))
      .tag("x.msg.react");
}
consteval auto json_schema(knot::type<direct_delete>) { return knot::schema<direct_delete>().tag("x.direct.del"); }

}  // namespace event
// The params, chosen by the event; any other event's kept as its JSON text.
using params_t = knot::tagged<"event", event::info, event::info_probe, event::info_probe_check, event::info_probe_ok, event::ok,
                              event::message_new, event::message_update, event::message_delete, event::message_react, event::file_description,
                              event::group_invite, event::group_accept, event::group_member_info,
                              event::direct_delete, knot::raw>;

struct message {
  std::optional<std::string> v;           // the sender's versions
  std::optional<std::string> message_id;  // its shared id (base64), where the event has one
  std::string event;
  params_t params;
};
consteval auto json_schema(knot::type<message>) { return knot::schema<message>().member<"message_id">(knot::key("msgId")); }

// ---- reading and writing ---------------------------------------------------------

namespace errors {
struct decompressing {
  quay::compression::error error;
};
struct reading {  // a body that is not the JSON of a chat message
  knot::error error;
};
}  // namespace errors
using error = spl::variant<errors::decompressing, errors::reading>;

namespace detail {
inline constexpr auto as_char = std::views::transform([](byte b) { return static_cast<char>(b); });
inline constexpr auto as_byte = std::views::transform([](char c) { return static_cast<byte>(c); });
}  // namespace detail

// The chat messages a connection's message body carries: decompressed where
// it is a compressed batch, each body one message or an array of them.
template <compression::detail::contiguous_bytes R>
std::expected<std::vector<message>, error> messages_of(const R& body) {
  auto bodies = compression::bodies_of(body);
  if (!bodies) return std::unexpected(errors::decompressing{bodies.error()});
  std::vector<message> out;
  for (const auto& one : *bodies) {
    if (!one.empty() && one.front() == '[') {
      auto many = knot::try_read<std::vector<message>>(one | detail::as_char);
      if (!many) return std::unexpected(errors::reading{many.error()});
      std::ranges::move(*many, std::back_inserter(out));
    } else {
      auto single = knot::try_read<message>(one | detail::as_char);
      if (!single) return std::unexpected(errors::reading{single.error()});
      out.push_back(std::move(*single));
    }
  }
  return out;
}

// A message to send: the event's tag and params, our versions, its id.
template <class Event>
message message_of(Event params, std::optional<std::string> message_id = std::nullopt) {
  return message{std::string(versions), std::move(message_id), std::string(json_schema(knot::type<Event>{}).tag_name()), params_t(std::move(params))};
}

// A message as the body quay.connection sends: its JSON, compressed where
// long (a batch of one, as simplex-chat sends from chat version 8 on).
inline bytes body_of(const message& m, bool compress = true) {
  std::string json;
  knot::write(json, m);
  // The text as bytes: zstd and the ratchet want them contiguous.
  const auto plain = json | detail::as_byte | std::ranges::to<bytes>();
  if (!compress) return plain;
  const std::array pieces{compression::compress(plain)};
  bytes out;
  (void)compression::put_batch(out, pieces);  // one piece: it cannot fail
  return out;
}

// A file's description put together from its parts, by the message that
// offered the file: the whole text once the part saying it is complete comes.
class file_descriptions {
 public:
  // A file offered (x.msg.new with a file): its first part.
  std::optional<std::string> offered(const std::optional<std::string>& message_id, const file_invitation& file) {
    if (!message_id || !file.description) return std::nullopt;
    return add(*message_id, *file.description);
  }
  // A further part (x.msg.file.descr).
  std::optional<std::string> more(const event::file_description& d) { return add(d.message_id, d.description); }

 private:
  std::optional<std::string> add(const std::string& id, const file_description_part& part) {
    auto& parts = parts_[id];
    if (static_cast<std::int64_t>(parts.size()) != part.part) return std::nullopt;  // out of order: not ours to guess
    parts.push_back(part.text);
    if (!part.complete) return std::nullopt;
    auto whole = parts | std::views::join | std::ranges::to<std::string>();
    parts_.erase(id);
    return whole;
  }
  std::map<std::string, std::vector<std::string>> parts_;
};

}  // namespace quay::chat
