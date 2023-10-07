
output "PublicIP_of_Webserver" {
  value = aws_instance.web_server.public_ip

}

output "PublicIP_of_Web_server" {
  value = aws_instance.web_server.public_ip

}

output "cloudfront-domain" {
  value = aws_cloudfront_distribution.set16-cd.domain_name

}
output "database"{
  value = aws_db_instance.set16_db.endpoint
}
# output "Name-server" {
#   value = aws_route53_zone.set16-zone.name_servers
# }

