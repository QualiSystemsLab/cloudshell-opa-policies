package cloudshell

import input as tfplan

# --- Validate region ---

get_region(provider_name) = region{
    region_var_name:= trim_prefix(input.configuration.provider_config[provider_name].expressions.region.references[0], "var.")
    region:= tfplan.variables[region_var_name].value
}
get_region(provider_name) = region{
    region:= tfplan.configuration.provider_config[provider_name].expressions.region.constant_value
}

get_basename(path) = basename{
    arr:= split(path, "/")
    basename:= arr[count(arr)-1]
}

equals(a, b) {
  a == b
}

contains_case_insensitive(arr, elem) {
  lower_elem:= lower(elem)
  equals(lower(arr[_]), lower_elem)
}

deny[reason] {
    provider_name:= get_basename(tfplan.resource_changes[_].provider_name)
    region:= get_region(provider_name)
    allowed_regions:=["us-west-2", "eu-west-1"]
    not contains_case_insensitive(allowed_regions, region)
    reason:= concat(" ", array.concat([concat("", ["Invalid region: \"", region, "\"."]), "The allowed regions are:"], allowed_regions))
}


# --- validate private s3 bucket ---

deny[reason] {
    r = tfplan.resource_changes[_]
    r.mode == "managed"
    r.type == "aws_s3_bucket"
    r.change.after.acl != "private"

    reason := "Deployment of not private S3 bucket is not allowed"
}

import input.driverRequest.actions as cs_apps

forbidden_ports := ["23", "3389"]

deny[reason]{
    request := cs_apps[_]
    model := request.actionParams.deployment.deploymentPath
    attributes := request.actionParams.deployment.attributes[_]
    attributes.attributeName == concat(".", [model, "Private IP"])
    attributes.attributeValue != ""
    reason = "Custom Private IPs are not allowed"
}

deny[reason]{
    request := cs_apps[_]
    model := request.actionParams.deployment.deploymentPath
    attributes := request.actionParams.deployment.attributes[_]
    attributes.attributeName == concat(".", [model, "Inbound Ports"])
    ports := concat("", ["(^|\\D)(", concat("|", forbidden_ports), ")(\\D|$)"])
    regex.match(ports, attributes.attributeValue)
    reason = concat(" ", ["Opening access to the following ports is not allowed:", concat(", ", forbidden_ports)])
}
