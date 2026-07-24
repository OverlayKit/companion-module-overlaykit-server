import type { CompanionAdvancedFeedbackResult, DropdownChoice } from '@companion-module/base';
import type { VisibilityFeedbackState } from './runtime.js';
import type ModuleInstance from './main.js';

const EMPTY_BINDING = '__overlaykit_unavailable__';

export type FeedbacksSchema = {
  'visibility.state': {
    type: 'advanced';
    options: {
      binding: string;
    };
  };
};

const STYLES: Readonly<Record<VisibilityFeedbackState, CompanionAdvancedFeedbackResult>> = {
  active: { text: 'ACTIVE', color: 0xffffff, bgcolor: 0x147d3f },
  inactive: { text: 'INACTIVE', color: 0xffffff, bgcolor: 0x30343b },
  unknown: { text: 'UNKNOWN', color: 0x161616, bgcolor: 0xf0b429 },
  disconnected: { text: 'DISCONNECTED', color: 0xffffff, bgcolor: 0x35546f },
  failed: { text: 'FAILED', color: 0xffffff, bgcolor: 0xb42318 },
  unavailable: { text: 'UNAVAILABLE', color: 0xffffff, bgcolor: 0x6b7280 },
};

function choices(instance: ModuleInstance): DropdownChoice<string>[] {
  const bindings = instance.runtimeBindings().map((binding) => ({
    id: binding.id,
    label: `${binding.target === 'preview' ? 'Preview' : 'Program'}: ${binding.label}`,
  }));
  return [...bindings, { id: EMPTY_BINDING, label: 'No authorized controls' }];
}

export function updateFeedbacks(instance: ModuleInstance): void {
  const bindingChoices = choices(instance);
  instance.setFeedbackDefinitions({
    'visibility.state': {
      name: 'Visibility state',
      type: 'advanced',
      options: [
        {
          id: 'binding',
          type: 'dropdown',
          label: 'Component',
          choices: bindingChoices,
          default: bindingChoices[0]?.id ?? EMPTY_BINDING,
        },
      ],
      callback: (event) => STYLES[instance.visibilityFeedback(event.options.binding)],
    },
  });
}
