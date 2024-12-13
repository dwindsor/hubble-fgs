import { memo } from "react";

import { Props as IconProps, Icon } from "./Icon";

export type Props = Omit<IconProps, "children">;

export const HostIcon = memo(function HostIcon(props: Props) {
  return (
    <Icon {...props}>
      {(color) => (
        <>
          <rect width="24" height="24" rx="3" fill={color} />
          <path
            d="M13.68 13.16H10.32V19H7.04V5.14H10.32V10.46H13.68V5.14H16.96V19H13.68V13.16Z"
            fill="white"
          />
        </>
      )}
    </Icon>
  );
});
