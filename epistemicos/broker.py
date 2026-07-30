import queue
from typing import Any, Dict

class MessageBroker:
    def __init__(self):
        self._topics: Dict[str, queue.Queue] = {}

    def _get_or_create_topic(self, topic_name: str) -> queue.Queue:
        if topic_name not in self._topics:
            self._topics[topic_name] = queue.Queue()
        return self._topics[topic_name]

    def publish(self, topic_name: str, message: Any):
        """Publishes a message to the specified topic queue."""
        q = self._get_or_create_topic(topic_name)
        q.put(message)

    def consume(self, topic_name: str) -> Any:
        """Consumes a single message from the specified topic queue. Returns None if empty."""
        q = self._get_or_create_topic(topic_name)
        try:
            return q.get_nowait()
        except queue.Empty:
            return None

# Global mock instance representing a Kafka/RabbitMQ broker
kafka_mock = MessageBroker()
