"""
RabbitMQ publisher to route UNKNOWN attacks to ML Workers.
"""

import json
import logging
import os
import pika
from typing import Dict, Any

LOGGER = logging.getLogger("signature_engine.rabbitmq")

class RabbitMQPublisher:
    def __init__(self):
        self.host = os.getenv("RABBITMQ_HOST", "rabbitmq")
        self.port = int(os.getenv("RABBITMQ_PORT", "5672"))
        self.user = os.getenv("RABBITMQ_USER", "admin")
        self.password = os.getenv("RABBITMQ_PASSWORD", "adminpassword")
        self.queue_name = "unknown_attack_events"
        
        credentials = pika.PlainCredentials(self.user, self.password)
        parameters = pika.ConnectionParameters(self.host, self.port, '/', credentials)
        
        self.connection = pika.BlockingConnection(parameters)
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=self.queue_name, durable=True)

    def publish_unknown_attack(self, enriched_event: Dict[str, Any]):
        """Publish an unknown attack to the ML pipeline queue."""
        self.channel.basic_publish(
            exchange='',
            routing_key=self.queue_name,
            body=json.dumps(enriched_event),
            properties=pika.BasicProperties(
                delivery_mode=2,  # make message persistent
            )
        )
        LOGGER.info(f"Published unknown attack to RabbitMQ for event_id: {enriched_event.get('event_id')}")

    def close(self):
        if self.connection and not self.connection.is_closed:
            self.connection.close()