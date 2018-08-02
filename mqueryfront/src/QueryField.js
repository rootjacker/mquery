import React, {Component} from 'react';
import axios from 'axios';


class QueryField extends Component {
    constructor(props) {
        super(props);
        this.state = {
            "rawYara": props.rawYara,
        };

        this.handleInputChange = this.handleInputChange.bind(this);
        this.handleQuery = this.handleQuery.bind(this);
        this.handleEdit = this.handleEdit.bind(this);
    }

    componentDidMount() {

    }

    componentWillReceiveProps(newProps) {
        this.setState({
            rawYara: newProps.rawYara,
            isLocked: newProps.isLocked
        });
    }

    handleQuery(event, method) {
        axios.create()
            .post("http://localhost:5000/query", {"rawYara": this.state.rawYara, "method": method})
            .then(response => {
                if (method === 'query') {
                    this.props.updateQhash(response.data.query_hash, this.state.rawYara);
                } else if (method === 'parse') {
                    this.props.updateQueryPlan(response.data, this.state.rawYara);
                }
            })
            .catch(error => {
                let err = error.toString();

                if (error.response) {
                    err = error.response.data.error;
                }

                this.props.updateQueryError(err, this.state.rawYara);
            });

        event.preventDefault();
    }

    handleInputChange(event) {
        const target = event.target;
        const value = target.type === 'checkbox' ? target.checked : target.value;
        const name = target.name;

        this.setState({
            [name]: value
        });
    }

    handleEdit(event) {
        this.props.updateQhash(null);
    }

    render() {
        return (
            <div>
                <div className="btn-group mb-1">
                    <button className="btn btn-success btn-lg" name="query" type="submit" onClick={(event) => this.handleQuery(event, 'query')}>
                        <span className="fas fa-database"/> Query
                    </button>

                    {this.state.isLocked ? (
                        <button className="btn btn-secondary btn-lg" name="clone" type="submit" onClick={this.handleEdit}>
                            <span className="fas fa-clone"/> Edit
                        </button>
                    ) : (
                        <button className="btn btn-secondary btn-lg" name="parse" type="submit" onClick={(event) => this.handleQuery(event, 'parse')}>
                            <span className="fas fa-code"/> Parse
                        </button>
                    )}
                </div>
                <div className="form-group">
                    <textarea name="rawYara" className="form-control mquery-yara-input" onChange={this.handleInputChange} readOnly={this.state.isLocked} value={this.state.rawYara} />
                </div>
            </div>
        );
    }
}

export default QueryField;
