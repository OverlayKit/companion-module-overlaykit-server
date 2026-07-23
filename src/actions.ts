import type { DropdownChoice } from '@companion-module/base';
import type ModuleInstance from './main.js';

const EMPTY_BINDING = '__overlaykit_unavailable__';

export type ActionsSchema = {
  'visibility.show': {
    options: {
      binding: string;
    };
  };
  'visibility.hide': {
    options: {
      binding: string;
    };
  };
  'visibility.toggle': {
    options: {
      binding: string;
    };
  };
};

function choices(instance: ModuleInstance): DropdownChoice<string>[] {
  const bindings = instance.runtimeBindings().map((binding) => ({
    id: binding.id,
    label: `${binding.target === 'preview' ? 'Preview' : 'Program'}: ${binding.label}`,
  }));
  return bindings.length > 0 ? bindings : [{ id: EMPTY_BINDING, label: 'No authorized controls' }];
}

export function updateActions(instance: ModuleInstance): void {
  const bindingChoices = choices(instance);
  const option = {
    id: 'binding' as const,
    type: 'dropdown' as const,
    label: 'Component',
    choices: bindingChoices,
    default: bindingChoices[0]?.id ?? EMPTY_BINDING,
  };
  instance.setActionDefinitions({
    'visibility.show': {
      name: 'Show component',
      options: [option],
      callback: async (event) => {
        await instance.executeVisibility('show', event.options.binding);
      },
    },
    'visibility.hide': {
      name: 'Hide component',
      options: [option],
      callback: async (event) => {
        await instance.executeVisibility('hide', event.options.binding);
      },
    },
    'visibility.toggle': {
      name: 'Toggle component',
      options: [option],
      callback: async (event) => {
        await instance.executeVisibility('toggle', event.options.binding);
      },
    },
  });
}
