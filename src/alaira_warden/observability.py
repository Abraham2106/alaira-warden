from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from alaira_warden.config import Settings


def instrument(app, settings: Settings) -> TracerProvider:
    provider = TracerProvider(
        resource=Resource.create({"service.name": settings.otel_service_name})
    )
    if settings.otel_exporter_otlp_endpoint:
        exporter = OTLPSpanExporter(
            endpoint=settings.otel_exporter_otlp_endpoint.rstrip("/") + "/v1/traces"
        )
        provider.add_span_processor(BatchSpanProcessor(exporter))
    # No request/response header capture or application payload attributes.
    FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)
    return provider
