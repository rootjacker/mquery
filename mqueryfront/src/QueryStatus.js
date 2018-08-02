import React, {Component} from 'react';
import axios from "axios/index";


function MatchItem(props) {
    let metadata = <span className="badge badge-dark">not yet loaded</span>;

    if (props.metadata_available) {
        metadata = Object.keys(props.metadata).map(
            (m) => <a href={props.metadata[m].url}>
                <span className="badge badge-info">{props.metadata[m].display_text}</span>
            </a>
        );
    }

    return (
        <tr>
            <td><a href={props.download_url}>{props.matched_path}</a></td>
            <td>{metadata}</td>
        </tr>
    );
}

class QueryStatus extends Component {
    constructor(props) {
        super(props);

        this.state = {
            qhash: props.qhash,
            status: null,
            queryPlan: null,
            queryError: null
        };

        this.timeout = null;

        this.reloadStatus = this.reloadStatus.bind(this);
    }

    componentWillMount() {
        this.reloadStatus();
    }

    componentWillUnmount() {
        if (this.timeout !== null) {
            clearTimeout(this.timeout);
        }
    }

    componentWillReceiveProps(newProps) {
        if (this.state.qhash !== newProps.qhash) {
            this.setState({
                status: null
            });
        }

        this.setState({
            qhash: newProps.qhash,
            queryPlan: newProps.queryPlan,
            queryError: newProps.queryError
        });
    }

    reloadStatus() {
        if (this.state.qhash) {
            axios
                .get("http://localhost:5000/status/" + this.state.qhash)
                .then(response => {
                    this.setState({"status": response.data});
                    this.timeout = setTimeout(() => this.reloadStatus(), 1000);
                });
        } else {
            this.timeout = setTimeout(() => this.reloadStatus(), 1000);
        }
    }

    render() {
        if (this.state.queryError) {
            return <div className="alert alert-danger">
                <h2>Error occurred</h2>
                {this.state.queryError}
            </div>;
        }

        if (this.state.queryPlan) {
            return <div style={{marginTop: "55px"}}>
                <h4>Parse result</h4>
                <div className="form-group">
                    <label>Rule name:</label>
                    <input type="" className="form-control" value={this.state.queryPlan.rule_name} readOnly />
                </div>
                <div className="form-group">
                    <label>Query plan</label>
                    <textarea className="form-control" rows="6" value={this.state.queryPlan.parsed} readOnly />
                </div>
            </div>;
        }

        if (!this.state.status || !this.state.qhash) {
            return <div />;
        }

        let progress = Math.floor(this.state.status.job.files_processed * 100 / this.state.status.job.total_files);

        if (this.state.status.job.total_files <= 0) {
            progress = 100;
        }

        const matches = this.state.status.matches.map((match) =>
            <MatchItem {...match} key={match.matched_path}/>
        );

        let progressBg = 'bg-info';

        if (this.state.status.job.status === 'done') {
            progressBg = 'bg-success';
        }

        const lenMatches = this.state.status.matches.length;

        return (
            <div>
                <div className="progress" style={{marginTop: "55px"}}>
                    <div className={"progress-bar " + progressBg} role="progressbar" style={{"width": progress + "%"}}>
                        {progress}%
                    </div>
                </div>
                <div className="row mq-n2margin pt-3">
                    <div className="col-md-2">
                        <p>Matches: <span>{lenMatches}</span></p>
                    </div>
                    <div className="col-md-3">
                        Status: <span className="badge badge-dark">{this.state.status.job.status}</span>
                    </div>
                    <div className="col-md-5">
                        Processed: <span>{this.state.status.job.files_processed} / {this.state.status.job.total_files}</span>
                    </div>
                    <div className="col-md-2">
                        <button className="btn btn-danger btn-sm" onClick={this.handleCancelJob}>cancel</button>
                    </div>
                </div>
                <table className={"table table-striped table-bordered"}>
                    <thead>
                        <tr>
                            <th>File name</th>
                            <th>Metadata</th>
                        </tr>
                    </thead>
                    <tbody>
                        {matches}
                    </tbody>
                </table>
            </div>
        );
    }
}

export default QueryStatus;
