import { memo } from "react";
import { Endpoint } from "./Endpoint";

export interface EndpointsProps {
  endpoints: string[];
}

export const Endpoints = memo(function Endpoints(props: EndpointsProps) {
  return (
    <div>
      {props.endpoints.map((endpoint) => {
        return <Endpoint key={endpoint} endpoint={endpoint} />;
      })}
    </div>
  );
});
