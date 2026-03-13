const formatMarkdownAlert = (event) =>
  [
    `Threat: ${event.attackType}`,
    `Action: ${event.action}`,
    `Source: ${event.sourceIp}:${event.sourcePort}`,
    `Destination: ${event.destinationIp}:${event.destinationPort}`,
    `Confidence: ${event.confidence.toFixed(2)}`,
    `Provider: ${event.provider}`,
    `Explanation: ${event.explanation}`,
  ].join('\n');

const buildPayload = (destination, event) => {
  switch (destination.provider) {
    case 'slack':
      return {
        text: formatMarkdownAlert(event),
      };
    case 'discord':
      return {
        content: formatMarkdownAlert(event),
      };
    case 'teams':
      return {
        '@type': 'MessageCard',
        '@context': 'https://schema.org/extensions',
        summary: `NetGuard alert: ${event.attackType}`,
        themeColor: event.severity === 'critical' ? 'E81123' : 'FFB900',
        sections: [
          {
            activityTitle: `NetGuard alert: ${event.attackType}`,
            facts: [
              { name: 'Action', value: event.action },
              { name: 'Source', value: `${event.sourceIp}:${event.sourcePort}` },
              { name: 'Destination', value: `${event.destinationIp}:${event.destinationPort}` },
              { name: 'Confidence', value: event.confidence.toFixed(2) },
              { name: 'Provider', value: event.provider },
            ],
            text: event.explanation,
          },
        ],
      };
    default:
      return {
        event: 'netguard.alert',
        payload: event,
      };
  }
};

const sendWebhook = async (destination, event) => {
  const response = await fetch(destination.url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'NetGuard-AI/1.0',
    },
    body: JSON.stringify(buildPayload(destination, event)),
  });

  if (!response.ok) {
    const responseText = await response.text();
    throw new Error(`${destination.name} responded with ${response.status}: ${responseText}`);
  }
};

export const dispatchAlertWebhooks = async (destinations, event) => {
  const enabledDestinations = destinations.filter(destination => destination.enabled && destination.url);
  const results = await Promise.allSettled(enabledDestinations.map(destination => sendWebhook(destination, event)));

  return {
    delivered: results.filter(result => result.status === 'fulfilled').length,
    failed: results.filter(result => result.status === 'rejected').length,
    results: results.map((result, index) => ({
      destination: enabledDestinations[index]?.name || `destination-${index + 1}`,
      success: result.status === 'fulfilled',
      error: result.status === 'rejected' ? result.reason instanceof Error ? result.reason.message : String(result.reason) : null,
    })),
  };
};
