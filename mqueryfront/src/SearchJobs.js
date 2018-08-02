import React, {Component} from 'react';
import {Link} from 'react-router-dom';
import ErrorBoundary from './ErrorBoundary';
import axios from 'axios';


class SearchJobRow extends Component {
    render() {
        const shortId = this.props.id.substr(0, 6);
        const submittedDate = (new Date(this.props.submitted * 1000)).toISOString();
        let rowClass;

        switch (this.props.status) {
            case "done": rowClass = "table-success"; break;
            case "pending": rowClass = "table-info"; break;
            default: rowClass = ""; break;
        }

        let cancelBtn = <button className="btn btn-sm btn-danger">cancel</button>;

        if (this.props.status === "done") {
            cancelBtn = "";
        }

        return <tr className={rowClass}>
            <td>
                <Link to={'/query/' + this.props.id} style={{fontFamily: "monospace"}}>{this.props.rule_name} ({shortId})</Link>
                <p style={{fontSize: "9px"}}>{submittedDate}</p>
            </td>
            <td>
                {this.props.status}
            </td>
            <td>
                {this.props.files_processed} / {this.props.total_files}
            </td>
            <td>
                {cancelBtn}
            </td>
        </tr>;
    }
}

class SearchJobs extends Component {
    constructor(props) {
        super(props);

        this.state = {
            jobs: [],
            error: null
        }
    }

    componentDidMount() {
        axios
            .get("http://localhost:5000/status/jobs")
            .then(response => {
                this.setState({"jobs": response.data.jobs});
            })
            .catch(error => {
                this.setState({"error": error});
            });
    }

    render() {
        const backendJobRows = this.state.jobs
            .map((job) =>
                <SearchJobRow {...job} key={job.id}/>
            );

        return (
            <ErrorBoundary error={this.state.error}>
                <div className="table-responsive">
                    <table className="table table-striped table-bordered">
                        <thead>
                        <tr>
                            <th>Job name</th>
                            <th>Status</th>
                            <th>Progress</th>
                            <th>Actions</th>
                        </tr>
                        </thead>
                        <tbody>
                        {backendJobRows}
                        </tbody>
                    </table>
                </div>
            </ErrorBoundary>
        );
    }
}

export default SearchJobs;
