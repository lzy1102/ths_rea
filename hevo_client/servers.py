from .markets import is_main_quote_server, supported_markets


class DataServerGroup:
    def __init__(self, host_or_ip="", port=0, service_tags=None, tag_string="", group_name=""):
        self.host_or_ip = host_or_ip
        self.port = port
        self.service_tags = list(service_tags or [])
        self.tag_string = tag_string
        self.group_name = group_name
        self.priority = "Primary"
        self.weight = 0

    @property
    def supported_markets(self):
        return supported_markets(self.service_tags)

    @property
    def is_main_quote_server(self):
        return is_main_quote_server(self.supported_markets)

    def __repr__(self):
        return "DataServerGroup(%s:%s tags=%s)" % (self.host_or_ip, self.port, ",".join(self.service_tags))


def parse_data_server_groups(value):
    if not value:
        return []
    groups = []
    for entry in value.split(","):
        if not entry:
            continue
        parts = entry.split(":")
        if len(parts) < 2:
            continue
        host_or_ip = parts[0]
        if not parts[1]:
            continue
        try:
            port = int(parts[1]) & 0xFFFF
        except ValueError:
            continue
        service_tags = [tag for tag in parts[2].split(";") if tag] if len(parts) > 2 else []
        tag_string = ""
        if len(parts) > 4:
            tag_string = parts[4]
        weight = 0
        if len(parts) > 5:
            try:
                weight = int(parts[5]) & 0xFFFF
            except ValueError:
                weight = 0
        group_name = parts[6] if len(parts) > 6 else ""
        group = DataServerGroup(host_or_ip, port, service_tags, tag_string, group_name)
        group.weight = weight
        groups.append(group)
        if len(parts) < 4:
            continue
        for sub in [item for item in parts[3].split("#") if item]:
            sub_parts = [item for item in sub.split("-") if item]
            if len(sub_parts) < 2:
                continue
            try:
                sub_port = int(sub_parts[1]) & 0xFFFF
            except ValueError:
                continue
            sub_tag = sub_parts[2] if len(sub_parts) > 2 else ""
            sub_weight = 0
            if len(sub_parts) > 3:
                try:
                    sub_weight = int(sub_parts[3]) & 0xFFFF
                except ValueError:
                    sub_weight = 0
            sub_group_name = sub_parts[4] if len(sub_parts) > 4 else ""
            sub_group = DataServerGroup(sub_parts[0], sub_port, service_tags, sub_tag, sub_group_name)
            sub_group.weight = sub_weight
            groups.append(sub_group)
    return groups


def select_main_quote_group(groups):
    for group in groups or []:
        if group.is_main_quote_server:
            return group
    for group in groups or []:
        if not group.tag_string:
            return group
    return None
