variable "name" {
  description = "The cluster name, e.g cdn"
}

variable "regions" {
  description = "Regions to launch in"
  type = list
  default = ["NYC1", "NYC3", "FRA1", "LON1", "AMS3", "SFO2", "SGP1", "TOR1"]
}

variable "ssh_key" {
  description = "SSH key filename to copy to the nodes"
  type = string
}

variable "instance_size" {
  description = "The instance size to use"
  default = "s-1vcpu-1gb"
}

variable "servers" {
  description = "Desired instance count"
  default     = 4
}

