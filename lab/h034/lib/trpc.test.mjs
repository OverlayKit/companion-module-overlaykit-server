import assert from 'node:assert/strict';
import { test } from 'node:test';
import { waitForEntityDefinition, waitForEntityDefinitionChoice } from './trpc.mjs';

function subscriptionWith(update) {
  return {
    subscribe(_input, handlers) {
      queueMicrotask(() => handlers.onData(update));
      return { unsubscribe() {} };
    },
  };
}

test('accepts an entity definition from an initial Companion inventory', async () => {
  const result = await waitForEntityDefinition(
    subscriptionWith({
      type: 'init',
      definitions: {
        connection: {
          'visibility.show': { label: 'Show component' },
        },
      },
    }),
    'connection',
    'visibility.show'
  );

  assert.equal(result.type, 'init');
});

test('accepts an entity definition added after the subscription starts', async () => {
  const result = await waitForEntityDefinition(
    subscriptionWith({
      type: 'add-connection',
      connectionId: 'connection',
      entities: {
        'visibility.state': { label: 'Visibility state' },
      },
    }),
    'connection',
    'visibility.state'
  );

  assert.equal(result.type, 'add-connection');
});

test('waits for a dynamic entity choice to enter the current Companion inventory', async () => {
  let subscriptions = 0;
  const procedure = {
    subscribe(_input, handlers) {
      subscriptions += 1;
      const choice =
        subscriptions === 1
          ? '__overlaykit_unavailable__'
          : 'component.visibility/preview/lower-third';
      queueMicrotask(() =>
        handlers.onData({
          type: 'init',
          definitions: {
            connection: {
              'visibility.show': {
                options: [{ id: 'binding', choices: [{ id: choice, label: choice }] }],
              },
            },
          },
        })
      );
      return { unsubscribe() {} };
    },
  };

  const definition = await waitForEntityDefinitionChoice(
    procedure,
    'connection',
    'visibility.show',
    'binding',
    'component.visibility/preview/lower-third'
  );

  assert.equal(subscriptions, 2);
  assert.equal(
    definition.options[0].choices[0].id,
    'component.visibility/preview/lower-third'
  );
});
