declare var showTooltip: (event: Event | undefined, text: string) => void;
declare var hideTooltip: () => void;

declare namespace Splunk {
  export var SearchManager: any;

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

  export var SearchBarView: any;
  export var SearchControlsView: any;
  export var TimelineView: any;

  export class SimpleSplunkView {
    public static extend(arg: {
      className?: string;
      options?: any;
      createView?: () => SimpleSplunkView;
      render: () => void;
      updateView: () => void;
    }): typeof SplunkView;
  }
}
