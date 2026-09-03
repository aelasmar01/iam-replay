variable "region" {
  description = "Region the fixture is deployed into."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for every resource this fixture creates, so teardown is unambiguous."
  type        = string
  default     = "iam-replay-fixture"
}

variable "schedule_expression" {
  description = "How often the workload runs. Faster means a usable oracle sooner."
  type        = string
  default     = "rate(5 minutes)"
}
