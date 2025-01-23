import { memo } from 'react';
import css from './ClusterNode.module.css';
import { NamespacesList } from './Namespace';
import { Host } from './Host';
import { NodeIcon } from './Icons/NodeIcon';
import { Collapsible } from './Collapsible';
import { useAppState } from '~/state/AppContext';
import { Statistic } from './Statistic';

export const ClusterNode = memo(function ClusterNode() {
  const state = useAppState();

  const stat = state.stat.node;

  const host = state.model.applicationModel?.host;
  const namespaces = state.model.applicationModel?.namespaces ?? [];

  return (
    <li className={css.nodeItem}>
      <Collapsible
        initialOpened={true}
        summary={({ onClick }) => (
          <summary className={css.nodeName} onClick={onClick}>
            <div>
              <NodeIcon
                className={css.nodeIcon}
                size={14}
                color={stat.hasSuspiciousEvents ? '#d59011' : '#b8b8b8'}
              />
              <span>
                {state.model.nodeName} <Statistic stat={stat} />
              </span>
            </div>
          </summary>
        )}
      >
        <ul>
          {host && (
            <li>
              <Host host={host} />
            </li>
          )}
          <li>
            <NamespacesList namespaces={namespaces} />
          </li>
        </ul>
      </Collapsible>
    </li>
  );
});
