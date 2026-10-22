from .markets import is_main_quote_server_tags, parse_uint16, supported_markets


class DataServerGroup:
    def __init__(self, host_or_ip="", port=0, service_tags=None, tag_string="", group_name=""):
        self.host_or_ip = host_or_ip
        self.port = port
        self.service_tags = list(service_tags or [])
        self.tag_string = tag_string
        self.group_name = group_name
        self.priority = "Primary"
        self.weight = 0
        self.children = []

    @property
    def supported_markets(self):
        return supported_markets(self.service_tags)

    @property
    def is_main_quote_server(self):
        return is_main_quote_server_tags(self.service_tags)

    def __repr__(self):
        return "DataServerGroup(%s:%s tags=%s)" % (self.host_or_ip, self.port, ",".join(self.service_tags))


def _split_entry(entry):
    parts = entry.split(":")
    if len(parts) < 2:
        raise ValueError("invalid server entry: " + entry)
    if not parts[1]:
        return None
    port = parse_uint16(parts[1])
    if port is None:
        raise ValueError("invalid server port: " + parts[1])
    if len(parts) < 3:
        raise ValueError("invalid server entry: " + entry)
    service_tags = [tag for tag in parts[2].split(";") if tag]
    tag_string = parts[4] if len(parts) > 4 else ""
    group_name = parts[6] if len(parts) > 6 else ""
    return parts, port, service_tags, tag_string, group_name


def _parse_children(spec, service_tags):
    children = []
    for sub in [item for item in spec.split("#") if item]:
        sub_parts = [item for item in sub.split("-") if item]
        if len(sub_parts) < 2:
            continue
        port = parse_uint16(sub_parts[1])
        if port is None:
            raise ValueError("invalid child server port: " + sub_parts[1])
        child = DataServerGroup(
            sub_parts[0],
            port,
            service_tags,
            sub_parts[2] if len(sub_parts) > 2 else "",
            sub_parts[4] if len(sub_parts) > 4 else "",
        )
        child.priority = "Secondary"
        children.append(child)
    return children


def parse_data_server_groups(value, include_children=True):
    if not value:
        return []
    groups = []
    for entry in value.split(","):
        if not entry:
            continue
        parsed = _split_entry(entry)
        if parsed is None:
            continue
        parts, port, service_tags, tag_string, group_name = parsed
        group = DataServerGroup(parts[0], port, service_tags, tag_string, group_name)
        groups.append(group)
        if len(parts) < 4:
            continue
        for child in _parse_children(parts[3], service_tags):
            group.children.append(child)
            if include_children:
                groups.append(child)
    return groups


def select_main_quote_group(groups):
    for group in groups or []:
        if group.is_main_quote_server:
            return group
    for group in groups or []:
        if not group.tag_string:
            return group
    return None
