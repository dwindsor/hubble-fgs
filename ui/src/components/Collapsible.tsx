import { type ReactNode, memo, useCallback, useState } from "react";
import { useAppState } from "~/state/AppContext";

export interface Props {
  initialOpened?: boolean;
  summary: (arg: {
    opened: boolean;
    onClick: (event: React.MouseEvent) => void;
  }) => ReactNode;
  children: ReactNode | ReactNode[];
}

export const Collapsible = memo(function Collapsible(props: Props) {
  const state = useAppState();

  const [opened, setOpened] = useState(props.initialOpened ?? false);

  const onClick = useCallback(
    (event: React.MouseEvent) => {
      event.preventDefault();
      setOpened((prev) => !prev);
      state.changeTree();
    },
    [state],
  );

  return (
    <details open={opened}>
      {props.summary({ opened, onClick })}
      {opened && props.children}
    </details>
  );
});
