import { type ReactNode, memo, useCallback, useState } from "react";

export interface Props {
  initialOpened?: boolean;
  summary: (arg: {
    opened: boolean;
    onClick: (event: React.MouseEvent) => void;
  }) => ReactNode;
  children: ReactNode | ReactNode[];
}

export const Collapsible = memo(function Collapsible(props: Props) {
  const [opened, setOpened] = useState(props.initialOpened ?? false);

  const onClick = useCallback((event: React.MouseEvent) => {
    event.preventDefault();
    setOpened((prev) => !prev);
  }, []);

  return (
    <details open={opened}>
      {props.summary({ opened, onClick })}
      {opened && props.children}
    </details>
  );
});
