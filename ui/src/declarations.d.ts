declare namespace Splunk {
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  export let SearchManager: any;

  export class SplunkView {
    constructor(arg: {
      id: string;
      managerid?: string;
      earliest_time?: string;
      latest_time?: string;
    });

    render(): this;

    updateView: () => void;
  }

  export class TableView {
    constructor(arg: {
      id: string;
      managerid?: string;
      drilldown?: string;
      el: Element;
    });

    render(): void;
  }

  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  export let SearchBarView: any;
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  export let SearchControlsView: any;
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  export let TimelineView: any;

  // biome-ignore lint/complexity/noStaticOnlyClass: <explanation>
  export class SimpleSplunkView {
    public static extend(arg: {
      className?: string;
      // biome-ignore lint/suspicious/noExplicitAny: <explanation>
      options?: any;
      createView?: () => SimpleSplunkView;
      render: () => void;
      updateView: () => void;
    }): typeof SplunkView;
  }
}
