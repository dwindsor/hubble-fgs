import { memo } from "react";

import { colors } from "~/theme/colors";
import { Icon, type Props as IconProps } from "./Icon";

export type Props = Omit<IconProps, "children">;

export const ContainerIcon = memo(function ContainerIcon(props: Props) {
  return (
    <Icon {...props}>
      {(color) => (
        <>
          <rect width="24" height="24" rx="3" fill={color} />
          <path
            d="M4 5H20V3H4V5ZM20 9H4V7H20V9ZM9 13H15V11H21V20C21 20.5523 20.5523 21 20 21H4C3.44772 21 3 20.5523 3 20V11H9V13Z"
            fill={colors.page}
          />
        </>
      )}
    </Icon>
  );
});
