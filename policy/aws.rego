package aws

is_subnet {
	input.resource.aws_subnet
}

is_vpc {
	input.resource.aws_vpc
}

is_dynamodb_table {
	input.resource.aws_dynamodb_table
}

is_sqs_queue {
	input.resource.aws_sqs_queue
}

is_iam_role {
	input.resource.aws_iam_role
}

is_iam_role_policy {
	input.resource.aws_iam_role_policy
}

is_lambda_function {
	input.resource.aws_lambda_function
}

is_cloudwatch_log_group {
	input.resource.aws_cloudwatch_log_group
}

is_lambda_event_source_mapping {
	input.resource.aws_lambda_event_source_mapping
}

is_lambda_permission {
	input.resource.aws_lambda_permission
}

is_sns_topic {
	input.resource.aws_sns_topic
}

is_sns_topic_subscription {
	input.resource.aws_sns_topic_subscription
}
