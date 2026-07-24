import { createTRPCClient, createWSClient, wsLink } from '@trpc/client';
import { WebSocket } from 'ws';

export function createCompanionClient(url) {
  const socketClient = createWSClient({
    url,
    WebSocket,
    keepAlive: { enabled: true },
  });
  const client = createTRPCClient({
    links: [wsLink({ client: socketClient })],
  });
  return {
    client,
    async close() {
      await socketClient.close();
    },
  };
}

export function firstSubscription(procedure, input, predicate = () => true, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    let subscription;
    const timer = setTimeout(() => {
      subscription?.unsubscribe();
      reject(new Error(`Companion subscription timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    subscription = procedure.subscribe(input, {
      onData(value) {
        if (!predicate(value)) return;
        clearTimeout(timer);
        subscription?.unsubscribe();
        resolve(value);
      },
      onError(error) {
        clearTimeout(timer);
        reject(error);
      },
    });
  });
}

export async function waitForConnectionStatus(client, connectionId, predicate, timeoutMs = 20_000) {
  return new Promise((resolve, reject) => {
    let lastStatus = null;
    let subscription;
    const timer = setTimeout(() => {
      subscription?.unsubscribe();
      reject(
        new Error(
          `Companion connection ${connectionId} did not reach the expected status after ${timeoutMs}ms; last status: ${JSON.stringify(lastStatus)}`
        )
      );
    }, timeoutMs);
    subscription = client.instances.statuses.watch.subscribe(undefined, {
      onData(update) {
        const status =
          update?.type === 'init'
            ? update.statuses?.[connectionId]
            : update?.instanceId === connectionId
              ? update.status
              : undefined;
        if (status === undefined) return;
        lastStatus = status;
        if (!predicate(status)) return;
        clearTimeout(timer);
        subscription?.unsubscribe();
        resolve(status);
      },
      onError(error) {
        clearTimeout(timer);
        reject(error);
      },
    });
  });
}

export async function waitForEntityDefinition(
  procedure,
  connectionId,
  definitionId,
  timeoutMs = 10_000
) {
  return firstSubscription(
    procedure,
    undefined,
    (update) => {
      if (update?.type === 'init') {
        return update.definitions?.[connectionId]?.[definitionId] !== undefined;
      }
      if (update?.connectionId !== connectionId) return false;
      if (update.type === 'add-connection') {
        return update.entities?.[definitionId] !== undefined;
      }
      if (update.type === 'update-connection') {
        return update.added?.[definitionId] !== undefined;
      }
      return false;
    },
    timeoutMs
  );
}

function definitionHasChoice(definition, optionId, choiceId) {
  const option = definition?.options?.find((candidate) => candidate.id === optionId);
  return option?.choices?.some((choice) => choice.id === choiceId) === true;
}

export async function waitForEntityDefinitionChoice(
  procedure,
  connectionId,
  definitionId,
  optionId,
  choiceId,
  timeoutMs = 10_000
) {
  const startedAt = Date.now();
  let observedChoices = [];
  while (Date.now() - startedAt < timeoutMs) {
    const update = await firstSubscription(
      procedure,
      undefined,
      (candidate) => candidate?.type === 'init',
      Math.min(2_000, timeoutMs)
    );
    const definition = update.definitions?.[connectionId]?.[definitionId];
    const option = definition?.options?.find((candidate) => candidate.id === optionId);
    observedChoices = option?.choices?.map((choice) => choice.id) ?? [];
    if (definitionHasChoice(definition, optionId, choiceId)) return definition;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(
    `Companion definition ${definitionId} did not expose ${optionId}=${choiceId} after ${timeoutMs}ms; observed choices: ${JSON.stringify(observedChoices)}`
  );
}

export async function controlIdAt(client, location) {
  const update = await firstSubscription(client.pages.watch, undefined);
  if (update?.type !== 'init') throw new Error('Companion page inventory did not initialize');
  const pageId = update.order[location.pageNumber - 1];
  const page = update.pages[pageId];
  return page?.controls?.[location.row]?.[location.column] ?? null;
}
