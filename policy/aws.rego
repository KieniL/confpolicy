package aws

is_subnet {
	input.resource.aws_subnet
}

is_vpc {
	input.resource.aws_vpc
}

is_dynamodb_table {
	aws_dynamodb_table
}

is_sqs_queue {
	aws_sqs_queue
}

is_iam_role {
	aws_iam_role
}

is_iam_role_policy {
	aws_iam_role_policy
}

is_lambda_function {
	aws_lambda_function
}

is_cloudwatch_log_group {
	aws_cloudwatch_log_group
}

is_lambda_event_source_mapping {
	aws_lambda_event_source_mapping
}

is_lambda_permission {
	aws_lambda_permission
}

is_sns_topic {
	aws_sns_topic
}

is_sns_topic_subscription {
	aws_sns_topic_subscription
}
