# Rules Syntax

The Wazuh ruleset, combined with any custom rules, analyzes incoming events. It generates alerts when all specified conditions within a rule are met. The ruleset is constantly expanding and improving thanks to the collaborative efforts of our developers and growing community.

## Options

Below, you can find a description of the XML labels used to configure rules.

| Option | Values | Description |
| --- | --- | --- |
| [rule](#rules-rule) | See this [table](#rules-rule) below. | Declares a new rule and its defining options. |
| [match](#rules-match) | Any [regular expression](regex.html). | Attempts to find a match in the log using [sregex](regex.html#sregex-os-match-syntax) by default, deciding if the rule should be triggered. |
| [regex](#regex-rules) | Any [regular expression](regex.html). | Does the same as `match`, but with [regex](regex.html#os-regex-syntax) as default. |
| [decoded\_as](#decoded-as) | Any decoder's name. | Matches with logs that have been decoded by a specific decoder. |
| [category](#rules-category) | Any [type](decoders.html#decoders-type). | Matches logs with the corresponding decoder's [type](decoders.html#decoders-type). |
| [field](#rules-field) | Name and any [regular expression](regex.html). | Compares a field extracted by the decoder in [order](decoders.html#decoders-order) with a regular expression. |
| [srcip](#srcip) | Any IP address. | Compares the IP address with the IP decoded as `srcip`. |
| [dstip](#dstip) | Any IP address. | Compares the IP address with the IP decoded as `dstip`. |
| [srcport](#rules-srcport) | Any [regular expression](regex.html). | Compares a regular expression representing a port with a value decoded as `srcport`. |
| [dstport](#rules-dstport) | Any [regular expression](regex.html). | Compares a regular expression representing a port with a value decoded as `dstport`. |
| [data](#data) | Any [regular expression](regex.html). | Compares a regular expression representing data with a value decoded as `data`. |
| [extra\_data](#rules-extra-data) | Any [regular expression](regex.html). | Compares a regular expression representing extra data with a value decoded as `extra_data`. |
| [user](#rules-user) | Any [regular expression](regex.html). | Compares a regular expression representing a user with a value decoded as `user`. |
| [system\_name](#rules-sys-name) | Any [regular expression](regex.html). | Compares a regular expression representing a system name with a value decoded as `system_name`. |
| [program\_name](#rules-prog-name) | Any [regular expression](regex.html). | Compares a regular expression representing a program name with a value pre-decoded as `program_name`. |
| [protocol](#rules-protocol) | Any [regular expression](regex.html). | Compares a regular expression representing a protocol with a value decoded as `protocol`. |
| [hostname](#rules-hostname) | Any [regular expression](regex.html). | Compares a regular expression representing a hostname with a value pre-decoded as `hostname`. |
| [time](#time) | Any time range. e.g. (hh:mm-hh:mm) | Checks if the event was generated during that time range. |
| [weekday](#weekday) | monday - sunday, weekdays, weekends | Checks whether the event was generated during certain weekdays. |
| [id](#rules-id) | Any [regular expression](regex.html). | Compares a regular expression representing an ID with a value decoded as `id` |
| [url](#rules-url) | Any [regular expression](regex.html). | Compares a regular expression representing a URL with a value decoded as `url` |
| [location](#rules-location) | Any [regular expression](regex.html). | Compares a regular expression representing a location with a value pre-decoded as `location`. |
| [action](#rules-action) | Any String or [regular expression](regex.html). | Compares a string or regular expression representing an action with a value decoded as `action`. |
| [status](#rules-status) | Any [regular expression](regex.html). | Compares a regular expression representing a status with a value decoded as `status`. |
| [srcgeoip](#rules-srcgeoip) | Any [regular expression](regex.html). | Compares a regular expression representing a GeoIP source with a value decoded as `srcgeoip`. |
| [dstgeoip](#rules-dstgeoip) | Any [regular expression](regex.html). | Compares a regular expression representing a GeoIP destination with a value decoded as `dstgeoip`. |
| [if\_sid](#if-sid) | A list of rule IDs separated by commas or spaces. | Similar to parent decoder, it matches when a rule ID on the list has previously matched. |
| [if\_group](#if-group) | Any group name. | Matches if the indicated group has matched before. |
| [if\_level](#if-level) | Any level from 1 to 16. | Matches if that level has already been triggered by another rule. |
| [if\_matched\_sid](#if-matched-sid) | Any rule ID (Number). | Similar to `if_sid` but it will only match if the ID has been triggered in a period of time. |
| [if\_matched\_group](#if-matched-group) | Any group name. | Similar to `if_group` but it will only match if the group has been triggered in a period of time. |
| [same\_id](#same-id) | None. | The decoded `id` must be the same. |
| [different\_id](#different-id) | None. | The decoded `id` must be different. |
| [same\_srcip](#same-srcip) | None. | The decoded `srcip` must be the same. |
| [different\_srcip](#different-srcip) | None. | The decoded `srcip` must be different. |
| [same\_dstip](#same-dstip) | None. | The decoded `dstip` must be the same. |
| [different\_dstip](#different-dstip) | None. | The decoded `dstip` must be different. |
| [same\_srcport](#same-srcport) | None. | The decoded `srcport` must be the same. |
| [different\_srcport](#different-srcport) | None. | The decoded `srcport` must be different. |
| [same\_dstport](#same-dstport) | None. | The decoded `dstport` must be the same. |
| [different\_dstport](#different-dstport) | None. | The decoded `dstport` must be different. |
| [same\_location](#same-location) | None. | The `location` must be the same. |
| [different\_location](#different-location) | None. | The `location` must be different. |
| [same\_srcuser](#same-srcuser) | None. | The decoded `srcuser` must be the same. |
| [different\_srcuser](#different-srcuser) | None. | The decoded `srcuser` must be different. |
| [same\_user](#same-user) | None. | The decoded `user` must be the same. |
| [different\_user](#different-user) | None. | The decoded `user` must be different. |
| [same\_field](#same-field) | None. | The decoded `field` must be the same as the previous ones. |
| [different\_field](#different-field) | None. | The decoded `field` must be different from the previous ones. |
| [same\_protocol](#same-protocol) | None. | The decoded `protocol` must be the same. |
| [different\_protocol](#different-protocol) | None. | The decoded `protocol` must be different. |
| [same\_action](#same-action) | None. | The decoded `action` must be the same. |
| [different\_action](#different-action) | None. | The decoded `action` must be different. |
| [same\_data](#same-data) | None. | The decoded `data` must be the same. |
| [different\_data](#different-data) | None. | The decoded `data` must be different. |
| [same\_extra\_data](#same-extra-data) | None. | The decoded `extra_data` must be the same. |
| [different\_extra\_data](#different-extra-data) | None. | The decoded `extra_data` must be different. |
| [same\_status](#same-status) | None. | The decoded `status` must be the same. |
| [different\_status](#different-status) | None. | The decoded `status` must be different. |
| [same\_system\_name](#same-system-name) | None. | The decoded `system_name` must be the same. |
| [different\_system\_name](#different-system-name) | None. | The decoded `system_name` must be different. |
| [same\_url](#same-url) | None. | The decoded `url` must be the same. |
| [different\_url](#different-url) | None. | The decoded `url` must be different. |
| [same\_srcgeoip](#same-srcgeoip) | None. | The decoded `srcgeoip` must the same. |
| [different\_srcgeoip](#different-srcgeoip) | None. | The decoded `srcgeoip` must be different. |
| [same\_dstgeoip](#same-dstgeoip) | None. | The decoded `dstgeoip` must the same. |
| [different\_dstgeoip](#different-dstgeoip) | None. | The decoded `dstgeoip` must be different. |
| [description](#description) | Any String. | Provides a human-readable description to explain the purpose of the rule. Always use this field when creating custom rules. |
| [list](#list) | Path to the CDB file. | Perform a CDB lookup using a [CDB list](../cdb-list.html). |
| [info](#info) | Any String. | Extra information using certain attributes. |
| [options](#rules-options) | See the table [below](#rules-options). | Additional rule options that can be used. |
| [check\_diff](#check-diff) | None. | Determines when the output of a command changes. |
| [group](#group) | Any String. | Add additional groups to the alert. |
| [mitre](#rules-mitre) | See [Mitre table](#rules-mitre) below. | Contains Mitre Technique IDs that fit the rule |
| [var](#var) | Name for the variable. Most used: [BAD\_WORDS](#bad-words) | Defines a variable that can be used anywhere inside the same file. |

### group

Groups categorize alerts. They allow filtering related alerts in the Wazuh dashboard.

The default Wazuh ruleset already includes rules that use groups like `syscheck,`, `attack,`, and `syslog,`. As an example, you can filter alerts for these categories by querying `rule.groups: attack` or `rule.groups: (syscheck OR syslog)` in the Wazuh dashboard.

Every rule must belong to at least one group. To specify one or more groups for a rule, enclose the rule definition with the `<group name="GROUP1_NAME,GROUP2_NAME,">` element. For example:

```
<group name="limits,">
 <rule id="100234" level="3">
    <if_sid>230</if_sid>
    <field name="alert_type">normal</field>
    <description>The file limit set for this agent is $(file_limit). Now, $(file_count) files are being monitored.</description>
  </rule>
</group>
```

You can also specify additional groups by including the `<group>` element within the rule definition. For example:

```
<group name="limits,">
  <rule id="100234" level="3">
    <if_sid>230</if_sid>
    <field name="alert_type">normal</field>
    <description>The file limit set for this agent is $(file_limit). Now, $(file_count) files are being monitored.</description>
   <group>syscheck,fim_db_state,</group>
 </rule>
</group>
```

To define rules that trigger only if another rule in a specific group has triggered, check the [if\_group](#if-group) and [if\_matched\_group](#if-matched-group) options.

### rule

`<rule>` is the label that starts the block defining a *rule*. In this section, we describe the various options associated with this label.

|  |  |  |
| --- | --- | --- |
| level | Definition | Specifies the level of the rule. Alerts and responses use this value. |
| Allowed values | 0 to 16 |
| id | Definition | Specifies the ID of the rule. |
| Allowed values | Any number from 1 to 999999 |
| maxsize | Definition | Specifies the maximum size of the event. |
| Allowed values | Any number from 1 to 9999 |
| frequency | Definition | Number of times the rule must match before generating an alert. |
| Allowed values | Any number from 2 to 9999 |
| timeframe | Definition | The timeframe in seconds. This option is intended to be used with the frequency option. |
| Allowed values | Any number from 1 to 99999 |
| ignore | Definition | The time (in seconds) to ignore this rule after it triggers(to avoid floods). |
| Allowed values | Any number from 1 to 999999 |
| overwrite | Definition | Used to replace a rule with local changes. To maintain consistency between loaded rules, `if_sid`, `if_group`, `if_level`, `if_matched_sid`, and `if_matched_group` labels are not taken into account when overwriting a rule. If any of these are encountered, the original value prevails. |
| Allowed values | yes, no |
| noalert | Definition | Does not trigger an alert if the rule matches. |
| Allowed values | `0` (alerts, value by default) or `1` (no alerts). If `noalert` is set to `1`, the event continues analyzing other rules despite the rule matches. |

Example:

```
<rule id="50180" level="10" frequency="8" timeframe="120" ignore="60">
  <if_matched_sid>50125</if_matched_sid>
  <description>MySQL: Multiple errors.</description>
  <mitre>
    <id>T1499</id>
  </mitre>
  <group>service_availability,pci_dss_10.6.1,gpg13_4.3,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.6,tsc_CC7.2,tsc_CC7.3,</group>
</rule>
```

The rule with ID `50180` triggers a level 10 alert if rule `50125` matches 8 times within 120 seconds. To prevent floods, it is ignored for 60 seconds after triggering.

### match

Used as a requisite to trigger a rule. It will search for a match in the log event.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

Example:

```
<rule id="100001" maxsize="300" level="3">
  <if_sid>100200</if_sid>
  <match>Queue flood!</match>
  <description>Flooded events queue.</description>
</rule>
```

If the rule 100200 is matched and the log message contains the phrase `Queue flood!`, the rule 100001 triggers a level 3 alert.

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If `match` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### regex

Used as a requisite to trigger a rule. It will search for a match in the log event.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

Example:

```
<rule id="100001" level="3">
  <if_sid>100500</if_sid>
  <regex>\b(?:\d{1,3}\.){3}\d{1,3}\b</regex>
  <description>Matches any valid IP</description>
</rule>
```

If the rule 100500 is matched and the event contains any valid IPv4, the rule 100001 is triggered, generating a level 3 alert.

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osregex | osregex |
| osmatch |
| pcre2 |

If `regex` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### decoded\_as

Used as a requisite to trigger a rule. It will be triggered if the event has been decoded by a certain `decoder`. Useful to group rules and have child rules inherit from it.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any decoder name |

Example:

```
<rule id="53500" level="0">
  <decoded_as>smtpd</decoded_as>
  <description>OpenSMTPd grouping.</description>
</rule>
```

The rule will be triggered if the event was decoded by the `smtpd` decoder. You can create more rules specifically tailored for OpenSMTPd events that will inherit from this one.

### category

Used as a requisite to trigger a rule. It will be triggered if the `decoder` includes the log in the specified category.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [type](decoders.html#decoders-type) |

Example:

```
<rule id="1" level="0" noalert="1">
  <category>syslog</category>
  <description>Generic template for all syslog rules.</description>
</rule>
```

The rule will trigger if the log message has previously been decoded by the `syslog` decoder. However, since the level is set to 0, the event will not be displayed on the dashboard. Instead, it will be matched by other rules that might trigger alerts if needed.

### field

Used as a requisite to trigger a rule. It will check for a match in the content of a field extracted by the decoder.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

Below is the list of attributes.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| name | specifies the name of the field extracted by the decoder. | n/a | n/a |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osregex | osregex |
| osmatch |
| pcre2 |

Example:

```
<rule id="87100" level="0">
    <decoded_as>json</decoded_as>
    <field name="integration">virustotal</field>
    <description>VirusTotal integration messages.</description>
    <options>no_full_log</options>
</rule>
```

This rule groups events decoded from json that belong to an integration called [VirusTotal](../../capabilities/malware-detection/virus-total-integration.html). It checks the field decoded as `integration` and if its content is `virustotal`, the rule is triggered.

If the `field` option is declared multiple times within a rule, Wazuh evaluates them as *logical AND* conditions. This means that each field requirement must be met for the rule to trigger.

Example:

```
<rule id="100001" level="5">
    <decoded_as>json</decoded_as>
    <field name="program_name">powershell.exe</field>
    <field name="command">Set-MpPreference -DisableRealtimeMonitoring</field>
    <description>PowerShell used to disable Windows Defender real-time protection.</description>
</rule>
```

This rule triggers only when both of the following field values are present in a log:

* The field decoded as `program_name` contains `powershell.exe`.
* The field decoded as `command` contains `Set-MpPreference -DisableRealtimeMonitoring`.

By combining two fields, the rule ensures higher precision and reduces false positives.

### srcip

Used as a requisite to trigger a rule. It compares any IP address or CIDR block to an IP decoded as srcip.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any IP address |

Example:

```
<rule id="100105" level="8">
    <if_sid>100100</if_sid>
    <srcip>10.25.23.12</srcip>
    <description>Forbidden srcip has been detected.</description>
</rule>
```

This rule will trigger when that exact `scrip` has been decoded.

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the IP address | no | no |
| yes |

If `srcip` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### dstip

Used as a requisite to trigger a rule. It compares any IP address or CIDR block to an IP decoded as `dstip`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any IPv4 IP address |

Example:

```
<rule id="100110" level="5">
    <if_sid>100100</if_sid>
    <dstip negate=”yes”>198.168.41.30</dstip>
    <description>A different dstip has been detected.</description>
</rule>
```

This rule will trigger when a `dstip` different from `198.168.41.30` is detected.

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows you to negate the IP address | no | no |
| yes |

If the `dstip` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### srcport

Used as a requisite to trigger a rule. It will check the source port (decoded as `srcport`).

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

Example:

```
<rule id="100110" level="5">
    <if_sid>100100</if_sid>
    <srcport type="pcre2">^5000[0-7]$</srcport>
    <description>Source port $(srcport) is detected.</description>
</rule>
```

This rule will trigger when `srcport` is in the range of 50000 to 50007.

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `srcport` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### dstport

Used as a requisite to trigger a rule. It will check the destination port (decoded as `dstport`).

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `dstport` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### data

Used as a requirement to trigger a rule, it compares a regular expression representing a data with a value decoded as `data`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `data` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### extra\_data

Used as a requirement to trigger a rule, it compares a regular expression representing a data with a value decoded as `extra_data`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

Example:

```
<rule id="7301" level="0">
  <category>windows</category>
  <extra_data>^Symantec AntiVirus</extra_data>
  <description>Grouping of Symantec AV rules from eventlog.</description>
</rule>
```

This rule will trigger when the log belongs to `windows` category and the decoded field `extra_data` is: `Symantec AntiVirus`

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `extra_data` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### user

Used as a requirement to trigger a rule, it compares a regular expression representing a user with a value decoded as `user`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

Example:

```
May  9 08:58:13 my-server sudo[3856]: pam_unix(sudo:session): session opened for user foo by vagrant(uid=1000)
```

```
<rule id="140101" level="12">
  <if_group>authentication_success</if_group>
  <user negate="yes">wazuh|root</user>
  <description>Unexpected user successfully logged to the system.</description>
</rule>
```

This rule triggers when a user different from `root` or `wazuh` successfully logs in to the system.

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `user` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### system\_name

Used as a requirement to trigger a rule, it compares a regular expression representing a system name with a value decoded as `system_name`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `system_name` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### program\_name

Used as a requirement to trigger a rule, it compares a regular expression representing a program name with a value decoded as `program_name`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

Example:

```
<rule id="1005" level="5">
  <program_name>syslogd</program_name>
  <match>^restart</match>
  <description>Syslogd restarted.</description>
  <group>pci_dss_10.6.1,gpg13_10.1,gpg13_4.14,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.6,</group>
</rule>
```

The rule will trigger when the program Syslogd is restarted.

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `program_name` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### protocol

Used as a requirement to trigger a rule, it compares a regular expression representing a protocol with a value decoded as `protocol`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `protocol` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### hostname

Used as a requirement to trigger a rule, it compares a regular expression representing a hostname with a value decoded as `hostname`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

Example:

```
<rule id="2931" level="0">
  <hostname>yum.log$</hostname>
  <match>^Installed|^Updated|^Erased</match>
  <description>Yum logs.</description>
</rule>
```

This rule will group rules for `Yum logs` when something is either being installed, updated or erased.

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `hostname` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### time

Used as a requisite to trigger a rule. It checks the event time based on the Wazuh server time, not the event timestamp. You must configure local time settings correctly to prevent unexpected triggers.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any time range (hh:mm-hh:mm, hh:mm am-hh:mm pm, hh-hh, hh am-hh pm) |

Example:

```
<rule id="17101" level="9">
  <if_group>authentication_success</if_group>
  <time>6 pm - 8:30 am</time>
  <description>Successful login during non-business hours.</description>
  <group>login_time,pci_dss_10.2.5,pci_dss_10.6.1,gpg13_7.1,gpg13_7.2,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_AU.6,</group>
</rule>
```

This rule triggers on successful logins occurring between 6 PM and 8 AM Wazuh server time.

### weekday

Used as a requisite to trigger a rule. It checks the event weekday based on the Wazuh server time, not the event timestamp. You must configure local time settings correctly to prevent unexpected triggers.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | monday - sunday, weekdays, weekends |

Example:

```
<rule id="17102" level="9">
  <if_group>authentication_success</if_group>
  <weekday>weekends</weekday>
  <description>Successful login during weekend.</description>
  <group>login_day,pci_dss_10.2.5,pci_dss_10.6.1,gpg13_7.1,gpg13_7.2,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_AU.6,</group>
</rule>
```

This rule triggers on successful logins during the weekend.

### id

Used as a requisite to trigger a rule. It compares a regular expression that represents an ID with a value decoded as `id`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

Example:

```
Feb  3 10:23:08 testsys kernel: usb 1-1.2: New USB device found, idVendor=0781, idProduct=5575
```

```
<rule id="81100" level="0">
    <decoded_as>kernel</decoded_as>
    <id>usb</id>
    <description>USB messages grouped.</description>
</rule>
```

This rule will check the content of the field `id` and group the logs whose decoded ID is `usb`.

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `id` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### url

Used as a requisite to trigger a rule. It compares a regular expression representing a URL with a value decoded as `url`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

Example:

```
<rule id="31102" level="0">
  <if_sid>31101</if_sid>
  <url>.jpg$|.gif$|favicon.ico$|.png$|robots.txt$|.css$|.js$|.jpeg$</url>
  <compiled_rule>is_simple_http_request</compiled_rule>
  <description>Ignored extensions on 400 error codes.</description>
</rule>
```

This rule is a child from a level 5 rule `31101` and becomes a level 0 rule when it confirms that the extensions are benign.

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `url` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### location

Used as a requisite to trigger a rule. It will check the content of the field `location` and try to find a match.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

The location identifies the origin of the input. If the event comes from an agent, its name and registered IP address (as it was added) is appended to the location.

Example of a location for a log pulled from `/var/log/syslog` in an agent with name `dbserver` and registered with IP `any`:

```
(dbserver) any->/var/log/syslog
```

The following components use a static location:

|  |  |
| --- | --- |
| **Component** | **Location** |
| Windows Eventchannel | EventChannel |
| Windows Eventlog | WinEvtLog |
| FIM (Syscheck) | syscheck |
| Rootcheck | rootcheck |
| Syscollector | syscollector |
| Vuln Detector | vulnerability-detector |
| Azure Logs | azure-logs |
| AWS S3 integration | aws-s3 |
| Docker integration | Wazuh-Docker |
| Osquery integration | osquery |
| SCA module | sca |

Example:

```
<rule id="24000" level="3">
  <location>osquery$</location>
  <description>osquery message</description>
</rule>
```

This rule groups logs that come from the `osquery` location.

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `location` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### action

Used as a requirement to trigger a rule, it compares a regular expression representing an action with a value decoded as `action`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

Example:

```
<rule id="4502" level="4">
  <if_sid>4500</if_sid>
  <action type="osregex">warning|WARN</action>
  <description>Netscreen warning message.</description>
</rule>
```

This rule will trigger a level 4 alert when the decoded action from Netscreen is `warning` or `WARN`.

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | string |
| osregex |
| pcre2 |

Note

Use `type` attribute only for regular expression match. It must be omitted if the action field tries to match a string.

If the `action` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### status

Compares a regular expression representing a status with a value decoded as `status`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

Example:

```
<rule id="213" level="7">
  <if_sid>210</if_sid>
  <status>aborted</status>
  <description>Remote upgrade could not be launched. Error: $(error).</description>
  <group>upgrade,upgrade_failure,</group>
</rule>
```

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `status` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### srcgeoip

Used as a requirement to trigger a rule, it compares a regular expression representing a source GeoIP with a value decoded as `srcgeoip`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `srcgeoip` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### dstgeoip

Used as a requirement to trigger a rule, it compares a regular expression representing a destination GeoIP with a value decoded as `dstgeoip`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any [regex](regex.html#os-regex-syntax), [sregex](regex.html#sregex-os-match-syntax) or [pcre2](regex.html#pcre2-syntax) expression. |

The attributes below are optional.

| Attribute | Description | Value range | Default value |
| --- | --- | --- | --- |
| negate | allows to negate the regular expression | no | no |
| yes |
| type | allows to set regular expression type | osmatch | osmatch |
| osregex |
| pcre2 |

If the `dstgeoip` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.
* The resulting value of an attribute corresponds to the one specified in the last label. If it is not specified, the default value is used.

### if\_sid

Used as a requisite to trigger a rule. This option matches if the log has previously matched a rule in the specified ID. It is similar to a child decoder, with the key difference that alerts can have as many descendants as necessary, whereas decoders cannot have "grandchildren".

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any rule ID. Multiple values must be separated by commas or spaces. |

Example:

```
<rule id="100110" level="5">
  <if_sid>100100, 100101</if_sid>
  <match>Error</match>
  <description>There is an error in the log.</description>
</rule>
```

The rule `100110` is triggered when either of the parent rules has matched and the logs contain the word `Error`.

### if\_group

Used as a requisite to trigger a rule. This option matches if the log has previously matched a rule in the specified group.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any Group |

Example:

```
<rule id="184676" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="sysmon.image">lsm.exe</field>
    <description>Sysmon - Suspicious Process - lsm.exe</description>
    <group>pci_dss_10.6.1,pci_dss_11.4,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.6,nist_800_53_SI.4,</group>
</rule>
```

The rule matches if the log has previously matched a rule in the `sysmon_event1` group and if the decoded field `sysmon.image` contains the value `lsm.exe`.

### if\_level

Matches if the level has matched before.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any level from 1 to 16 |

### if\_matched\_sid

Matches if an alert of the defined ID has been triggered in a set number of seconds.

This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any rule id |

Note

Rules at level 0 are discarded immediately and will not be used with `if_matched_rules`. The level must be at least 1, but you will have to add the `<no_log>` option to the rule to ensure it is not logged.

Example:

```
<rule id="30202" level="10" frequency="10" timeframe="120">
  <if_matched_sid>30201</if_matched_sid>
  <description>ModSecurity: Multiple attempts blocked.</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>access_denied,gdpr_IV_35.7.d,hipaa_164.312.b,modsecurity,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_SI.4,pci_dss_10.2.4,pci_dss_11.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
</rule>
```

The rule triggers when rule `30201` matches 10 times within 120 seconds.

### if\_matched\_group

Matches if an alert of the defined group has been triggered in a set number of seconds.

This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any Group |

Example:

```
<rule id="40113" level="12" frequency="8" timeframe="360">
  <if_matched_group>virus</if_matched_group>
  <description>Multiple viruses detected - Possible outbreak.</description>
  <group>virus,pci_dss_5.1,pci_dss_5.2,pci_dss_11.4,gpg13_4.2,gdpr_IV_35.7.d,nist_800_53_SI.3,nist_800_53_SI.4,</group>
</rule>
```

The rule will trigger when the group `virus` has been matched 8 times in the last 360 seconds.

### if\_fts

Makes the decoder that processed the event to take the [fts](decoders.html#decoders-fts) line into consideration.

|  |  |
| --- | --- |
| Example of use | <if\_fts /> |

Note

The dynamic filters `same_field` or `not_same_field` will not work with the static fields (`user`, `srcip`, `dstip`, etc.) and the specific ones have to be used instead.

### same\_id

Specifies that the decoded ID must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_id /> |

### different\_id

Specifies that the decoded id must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_id /> |

### same\_srcip

Specifies that the decoded source IP address must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_srcip /> |

The deprecated label `same_source_ip` works like an alias for `same_srcip`.

### different\_srcip

Specifies that the decoded source IP address must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_srcip /> |

The deprecated label `not_same_source_ip` works like an alias for `different_srcip`.

### same\_dstip

Specifies that the decoded destination IP address must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_dstip /> |

### different\_dstip

Specifies that the decoded destination IP address must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_dstip /> |

### same\_srcport

Specifies that the decoded source port must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_srcport /> |

### different\_srcport

Specifies that the decoded source port must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_srcport /> |

### same\_dstport

Specifies that the decoded destination port must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_dstport /> |

### different\_dstport

Specifies that the decoded destination port must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_dstport /> |

### same\_location

Specifies that the location must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_location /> |

### different\_location

Specifies that the decoded location must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_location /> |

### same\_srcuser

Specifies that the decoded source user must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_srcuser /> |

### different\_srcuser

Specifies that the decoded source user must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_srcuser /> |

### same\_user

Specifies that the decoded user must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_user /> |

### different\_user

Specifies that the decoded user must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_user /> |

### same\_field

The value of the dynamic field specified in this option must appear a certain number of times in previous events, as defined by the `frequency` attribute, within a time frame specified by the `timeframe` attribute.

|  |  |
| --- | --- |
| Example of use | <same\_field>key</same\_field> |

As an example of this option, check these rules:

```
<!-- {"key":"value", "key2":"AAAA"} -->
<rule id="100001" level="3">
  <decoded_as>json</decoded_as>
  <field name="key">value</field>
  <description>Testing JSON alert</description>
</rule>

<rule id="100002" level="10" frequency="4" timeframe="300">
  <if_matched_sid>100001</if_matched_sid>
  <same_field>key2</same_field>
  <description>Testing same_field option</description>
</rule>
```

Rule 100002 will fire when `key2` in the currently considered event is the same in four events that matched rule 100001 within the last 300 seconds. Consider the following event logs generated in less than 300 seconds:

```
{"key":"value", "key2":"AAAA"}
{"key":"value", "key2":"AAAA"}
{"key":"value", "key2":"BBBB"}
{"key":"value", "key2":"AAAA"}
{"key":"value", "key2":"CCCC"}
{"key":"value", "key2":"CCCC"}
{"key":"value", "key2":"AAAA"}
```

The last event will fire rule 100002 instead of 100001 because it found the value `AAAA` in three of the previous events. The corresponding alert looks like the following:

```
{
  "timestamp": "2020-03-04T03:00:28.973-0800",
  "rule": {
    "level": 10,
   "description": "Testing same_field option",
   "id": "100002",
    "frequency": 4,
    "firedtimes": 1,
    "mail": false,
    "groups": [
      "local"
    ]
  },
  "agent": {
    "id": "000",
    "name": "ubuntu"
  },
  "manager": {
    "name": "ubuntu"
  },
  "id": "1583319628.14426",
  "previous_output": "{\"key\":\"value\",\"key2\":\"AAAA\"}\n{\"key\":\"value\",\"key2\":\"AAAA\"}\n{\"key\":\"value\",\"key2\":\"AAAA\"}",
  "full_log": "{\"key\":\"value\",\"key2\":\"AAAA\"}",
  "decoder": {
    "name": "json"
  },
  "data": {
    "key": "value",
    "key2": "AAAA"
  },
  "location": "/root/test.log"
}
```

### different\_field

It is the opposite setting of `same_field`. The value of the dynamic field specified in this option must differ from those found in previous events a certain number of times. This is defined by the `frequency` attribute, within a time frame specified by the `timeframe` attribute.

|  |  |
| --- | --- |
| Example of use | <different\_field>key2</different\_field> |

### global\_frequency

Specifies that the events of all agents will be contemplated when using the frequency and `timeframe` options. By default, only the events generated by the same agent will be taken into account to increase the frequency counter for a rule.

|  |  |
| --- | --- |
| Example of use | <global\_frequency /> |

Note

Although the label contains the word global, this option works at manager level, not at cluster level.

### same\_protocol

Specifies that the decoded protocol must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_protocol /> |

### different\_protocol

Specifies that the decoded protocol must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_protocol /> |

### same\_action

Specifies that the decoded action must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_action /> |

### different\_action

Specifies that the decoded data must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_action /> |

### same\_data

Specifies that the decoded data must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_data /> |

### different\_data

Specifies that the decoded data must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_data /> |

### same\_extra\_data

Specifies that the decoded extra data must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_extra\_data /> |

### different\_extra\_data

Specifies that the decoded extra data must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_extra\_data /> |

### same\_status

Specifies that the decoded status must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_status /> |

### different\_status

Specifies that the decoded status must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_status /> |

### same\_system\_name

Specifies that the decoded system name must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_system\_name /> |

### different\_system\_name

Specifies that the decoded system name must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_system\_name /> |

### same\_url

Specifies that the decoded url must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_url /> |

### different\_url

Specifies that the decoded url must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_url /> |

### same\_srcgeoip

Specifies that the source GeoIP location must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_srcgeoip /> |

### different\_srcgeoip

Specifies that the source GeoIP location must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_srcgeoip /> |

Example:

As an example of these last options, check this rule:

```
<rule id=100005 level="0">
  <match> Could not open /home </match>
  <same_user />
  <different_srcgeoip />
  <same_dstport />
</rule>
```

The rule filters when the same `user` tries to open file `/home` but returns an error, on a different GeoIP and using the same destination port.

### same\_dstgeoip

Specifies that the destination GeoIP location must be the same. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <same\_dstgeoip /> |

### different\_dstgeoip

Specifies that the destination GeoIP location must be different. This option is used in conjunction with `frequency` and `timeframe`.

|  |  |
| --- | --- |
| Example of use | <different\_dstgeoip /> |

### description

Specifies a human-readable description of the rule to provide context to each alert regarding the nature of the events matched by it.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any string |

Examples:

```
<rule id="100015" level="2">
  ...
  <description>A timeout occurred.</description>
</rule>

<rule id="100035" level="4">
  ...
  <description>File missing. Root access unrestricted.</description>
</rule>
```

Since Wazuh version 3.3, it is possible to include any decoded field (static or dynamic) to the description message. You can use the following syntax: `$(field_name)` to add a field to the description.

Example:

```
<rule id="100005" level="8">
  <match>illegal user|invalid user</match>
  <description>sshd: Attempt to login using a non-existent user from IP $(attempt_ip)</description>
  <options>no_log</options>
</rule>
```

If `description` label is declared multiple times within the rule, the following rules apply:

* The resulting value is their concatenation.

### list

Perform a [Constant DataBase](../cdb-list.html) lookup using a CDB list. This is a fast on-disk database which will always find keys within two seeks of the file.

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Path to the CDB file to be used for lookup from the Wazuh directory. Must also be included in the `/var/ossec/etc/ossec.conf` file. |

|  |  |  |
| --- | --- | --- |
| Attribute | Description | |
| field | key in the CDB: srcip, srcport, dstip, dstport, extra\_data, user, url, id, hostname, program\_name, status, action, dynamic field. | |
| lookup | match\_key | Matches if the key value is present in the CDB list. Works by default. |
|  | not\_match\_key | Matches if the key value is not present in the CDB list. |
|  | match\_key\_value | Searches for a key value in the CDB list |
|  | address\_match\_key | IP address and the key to search within the CDB and will match if the key is present. |
|  | not\_address\_match\_key | IP address and the key to search and will match if it IS NOT present in the database. |
|  | address\_match\_key\_value | IP address to search in the CDB. It is compared with regex from attribute check\_value. |
| check\_value | regex for matching on the value pulled out of the CDB when using types: address\_match\_key\_value, match\_key\_value | |

Example:

```
<rule id="80780" level="3">
    <if_sid>80700</if_sid>
    <list field="audit.key" lookup="match_key_value" check_value="write">etc/lists/audit-keys</list>
    <description>Audit: Watch - Write access</description>
    <group>audit_watch_write,gdpr_IV_30.1.g,</group>
</rule>
```

The rule will look for `audit.key` in the CDB list. Where it will check if it is equal to `write`, in which case it will match and trigger a level 3 alert.

### info

You can add extra information through the following attributes:

|  |  |
| --- | --- |
| Default Value | n/a |
| Allowed values | Any string |

|  |  |  |
| --- | --- | --- |
| Attribute | Allowed values | Description |
| type | text | This is the default when no type is selected. Additional information about the alert/event. |
| link | Link to more information about the alert/event. |
| cve | The CVE Number related to this alert/event. |
| ovsdb | The osvdb id related to this alert/event. |

Example:

```
<rule id="5714" level="14" timeframe="120" frequency="3">
  <if_matched_sid>5713</if_matched_sid>
  <match>Local: crc32 compensation attack</match>
  <description>sshd: SSH CRC-32 Compensation attack</description>
  <info type="cve">2001-0144</info>
  <info type="link">http://www.securityfocus.com/bid/2347/info/</info>
  <group>exploit_attempt,pci_dss_11.4,pci_dss_6.2,gpg13_4.12,gdpr_IV_35.7.d,nist_800_53_SI.4,nist_800_53_SI.2,</group>
</rule>
```

The rule provides additional information about the threat it detects.

### options

Additional rule options.

| Attribute | Description |
| --- | --- |
| alert\_by\_email | Always alert by email. |
| no\_email\_alert | Never alert by email. |
| no\_log | Do not log this alert. |
| no\_full\_log | Do not include the `full_log` field in the alert. |
| no\_counter | Omit field `rule.firedtimes` in the JSON alert. |

Example:

```
<rule id="9800" level="8">
  <match>illegal user|invalid user</match>
  <description>sshd: Attempt to login using a non-existent user</description>
  <options>no_log</options>
</rule>
```

Note

Use one `<options>` tag for each option you want to add.

### check\_diff

Used to determine when the output of a command changes.

Example:

```
<rule id="534" level="1">
  <if_sid>530</if_sid>
  <match>ossec: output: 'w'</match>
  <check_diff />
  <options>no_log</options>
  <description>List of logged in users. It will not be alerted by default.</description>
</rule>
```

### mitre

Specifies the [MITRE ATT&CK](https://attack.mitre.org) technique ID or IDs that fit in well with the rule.

| Required label | Value |
| --- | --- |
| id | MITRE ATT&CK technique ID. |

Example:

```
<rule id="100002" level="10">
  <description>Attack technique sample.</description>
  <mitre>
    <id>T1110</id>
    <id>T1037</id>
  </mitre>
</rule>
```

### var

Defines a variable that can be used in any rule within the same rule file. It must be defined at the base level of the rule file, not inside a tagged section.

| Attribute | Value |
| --- | --- |
| name | Name for the variable. |

Example:

```
<var name="joe_folder">/home/joe/</var>

<group name="local,">

   <rule id="100001" level="5">
     <if_sid>550</if_sid>
    <field name="file">^$joe_folder</field>
    <description>A Joe's file was modified.</description>
     <group>ossec,pci_dss_10.6.1,gpg13_10.1,gdpr_IV_35.7.d,</group>
   </rule>

</group>
```

#### BAD\_WORDS

```
<var name="BAD_WORDS">error|warning|failure</var>
```

`BAD_WORDS` is a commonly used case of the `<var>` option.

It is used to include many words in the same variable. This variable can then be included into the rules to check if any of those words are in a caught event.

Example:

```
<var name="BAD_WORDS">error|warning|failure</var>
<group name="syslog,errors,">
  <rule id="XXXX" level="2">
   <match>$BAD_WORDS</match>
   <description>Error found.</description>
  </rule>
</group>
```